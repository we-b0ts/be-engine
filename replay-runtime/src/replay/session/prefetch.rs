//! Read ahead immutable Session responses without admitting any events.
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::{Arc, Mutex},
};

use crate::replay::native::{LoadedResponse, ResponsePreparation};
use anyhow::{Result, ensure};
use tokio::sync::Notify;

const WINDOW: usize = 256;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const READ_BATCH: usize = 32;

type ScheduledResponse = (usize, ResponsePreparation);

pub(in crate::replay) struct Responses {
    ordinals: HashMap<usize, usize>,
    shared: Arc<Shared>,
}

pub(in crate::replay) struct CloseOnDrop(Arc<Shared>);

#[derive(Default)]
struct Shared {
    state: Mutex<Window>,
    changed: Notify,
    available: Notify,
}

#[derive(Default)]
struct Window {
    first: usize,
    examined: usize,
    ready: BTreeMap<usize, LoadedResponse>,
    bytes: usize,
    peak_bytes: usize,
    hits: usize,
    prepared_hits: usize,
    misses: usize,
    waits: usize,
    producer_finished: bool,
    closed: bool,
}

impl fmt::Debug for Responses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Responses")
            .field("scheduled", &self.ordinals.len())
            .finish_non_exhaustive()
    }
}

impl Responses {
    pub(in crate::replay) fn start(responses: Vec<ScheduledResponse>) -> Option<Arc<Self>> {
        if responses.is_empty() {
            return None;
        }
        let ordinals = responses
            .iter()
            .enumerate()
            .map(|(ordinal, (index, _))| (*index, ordinal))
            .collect();
        let shared = Arc::new(Shared::default());
        tokio::spawn(produce(shared.clone(), responses));
        Some(Arc::new(Self { ordinals, shared }))
    }

    pub(in crate::replay) async fn take(&self, index: usize) -> Result<Option<LoadedResponse>> {
        let Some(&ordinal) = self.ordinals.get(&index) else {
            return Ok(None);
        };
        let mut waiting = false;
        loop {
            // notify_waiters records its generation even before the future is polled.
            let available = self.shared.available.notified();
            {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .expect("response prefetch poisoned");
                ensure!(
                    !state.closed,
                    "Session ended before prefetched response was delivered"
                );
                if let Some(response) = state.remove(ordinal) {
                    state.hits += 1;
                    state.prepared_hits += usize::from(response.has_source_preparation());
                    self.advance(&mut state, ordinal + 1);
                    return Ok(Some(response));
                }
                if ordinal < state.first || ordinal < state.examined || state.producer_finished {
                    state.misses += 1;
                    self.advance(&mut state, ordinal + 1);
                    return Ok(None);
                }
                if !waiting {
                    state.waits += 1;
                    waiting = true;
                }
                self.advance(&mut state, ordinal);
            }
            available.await;
        }
    }

    fn advance(&self, state: &mut Window, first: usize) {
        if first > state.first {
            state.advance(first);
            self.shared.changed.notify_one();
            self.shared.available.notify_waiters();
        }
    }

    pub(in crate::replay) fn close(&self) {
        self.shared.close();
    }

    pub(in crate::replay) fn close_on_drop(&self) -> CloseOnDrop {
        CloseOnDrop(self.shared.clone())
    }
}

impl Window {
    fn remove(&mut self, ordinal: usize) -> Option<LoadedResponse> {
        self.ready.remove(&ordinal).map(|response| {
            self.bytes -= response.prefetch_retained_bytes();
            response
        })
    }

    fn advance(&mut self, first: usize) {
        // Output starts are ordered, but different connection tasks can reach
        // the buffer in a different order. Earlier deliveries can load on demand.
        self.first = first;
        while self
            .ready
            .first_key_value()
            .is_some_and(|(queued, _)| *queued < self.first)
        {
            let (_, response) = self.ready.pop_first().expect("stale prefetched response");
            self.bytes -= response.prefetch_retained_bytes();
        }
    }

    fn insert(&mut self, ordinal: usize, response: LoadedResponse) {
        let bytes = response.prefetch_retained_bytes();
        if !self.closed && ordinal >= self.first && bytes <= MAX_BYTES - self.bytes {
            self.bytes += bytes;
            self.peak_bytes = self.peak_bytes.max(self.bytes);
            self.ready.insert(ordinal, response);
        }
    }
}

async fn produce(shared: Arc<Shared>, responses: Vec<ScheduledResponse>) {
    let mut responses = responses.into_iter().enumerate().peekable();
    while let Some(&(ordinal, _)) = responses.peek() {
        let batch_size = responses.len().min(READ_BATCH);
        let can_read = {
            let state = shared.state.lock().expect("response prefetch poisoned");
            if state.closed {
                return;
            }
            if ordinal < state.first {
                responses.next();
                continue;
            }
            ordinal + batch_size <= state.first + WINDOW && state.bytes < MAX_BYTES
        };
        if !can_read {
            shared.changed.notified().await;
            continue;
        }
        let batch = responses.by_ref().take(batch_size).collect();
        let worker = shared.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || load_batch(&worker, batch)).await {
            tracing::debug!(%error, "Session response prefetch worker stopped");
            break;
        }
    }
    shared
        .state
        .lock()
        .expect("response prefetch poisoned")
        .producer_finished = true;
    shared.available.notify_waiters();
}

fn load_batch(shared: &Shared, batch: Vec<(usize, ScheduledResponse)>) {
    for (ordinal, (_, response)) in batch {
        let available_bytes = {
            let state = shared.state.lock().expect("response prefetch poisoned");
            if state.closed {
                return;
            }
            if ordinal >= state.first {
                MAX_BYTES - state.bytes
            } else {
                0
            }
        };
        // Keep failures and responses without a memory estimate on the normal
        // delivery path. The producer can hold one transient decoded response.
        let response = if available_bytes > 0 {
            response.load(available_bytes).ok().flatten()
        } else {
            None
        };
        let mut state = shared.state.lock().expect("response prefetch poisoned");
        if let Some(response) = response {
            state.insert(ordinal, response);
        }
        state.examined = ordinal + 1;
        drop(state);
        shared.available.notify_waiters();
    }
}

impl Drop for Responses {
    fn drop(&mut self) {
        let (hits, prepared_hits, misses, waits, peak_bytes) = self.shared.close();
        tracing::info!(
            hits,
            prepared_hits,
            misses,
            waits,
            peak_bytes,
            "Session response prefetch"
        );
    }
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Shared {
    fn close(&self) -> (usize, usize, usize, usize, usize) {
        let mut state = self.state.lock().expect("response prefetch poisoned");
        state.closed = true;
        state.ready.clear();
        state.bytes = 0;
        let stats = (
            state.hits,
            state.prepared_hits,
            state.misses,
            state.waits,
            state.peak_bytes,
        );
        drop(state);
        self.changed.notify_one();
        self.available.notify_waiters();
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use hyper::body::Bytes;
    use serde_json::Value;
    use traffic_protocol::message::{
        MessageEncoder, ProjectedMessage, ProtocolMessage, StoredMessage,
    };

    struct TestResponse {
        bytes: usize,
        stored: bool,
    }

    fn stored_response(bytes: usize) -> ResponsePreparation {
        ResponsePreparation::decode_only(Arc::new(TestResponse {
            bytes,
            stored: true,
        }))
    }

    impl ProtocolMessage for TestResponse {
        fn project(&self) -> Result<ProjectedMessage> {
            unreachable!("the prefetcher does not project responses")
        }

        fn locate(&self, _: &Value) -> Result<Vec<String>> {
            unreachable!("the prefetcher does not apply field rules")
        }

        fn evidence(&self, _: &Value) -> Result<Value> {
            unreachable!("the prefetcher does not publish evidence")
        }
    }

    impl MessageEncoder for TestResponse {
        fn stored(&self) -> Option<&dyn StoredMessage> {
            self.stored.then_some(self)
        }

        fn prefetch_retained_bytes(&self) -> Option<usize> {
            Some(self.bytes)
        }

        fn encode(&self, _: &BTreeMap<String, Bytes>) -> Result<Bytes> {
            unreachable!("the prefetcher does not encode responses")
        }
    }

    impl StoredMessage for TestResponse {
        fn load(&self) -> Result<Arc<dyn MessageEncoder>> {
            Ok(Arc::new(Self {
                bytes: self.bytes,
                stored: false,
            }))
        }
    }

    #[tokio::test]
    async fn prefetch_returns_the_prepared_response_by_exchange_index() {
        let queue =
            Responses::start(vec![(9, stored_response(3)), (7, stored_response(5))]).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while queue.shared.state.lock().unwrap().ready.len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let decoded = queue.take(7).await.unwrap().unwrap();
        assert_eq!(decoded.prefetch_retained_bytes(), 5);
        assert!(
            queue.take(9).await.unwrap().is_none(),
            "earlier delivery can load on demand"
        );
    }

    #[tokio::test]
    async fn an_empty_window_waits_for_the_requested_response() {
        let shared = Arc::new(Shared::default());
        let queue = Arc::new(Responses {
            ordinals: HashMap::from([(7, 0)]),
            shared: shared.clone(),
        });
        let consumer = tokio::spawn(async move { queue.take(7).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while shared.state.lock().unwrap().waits == 0 {
                tokio::task::yield_now().await;
            }
            assert!(!consumer.is_finished());
            load_batch(&shared, vec![(0, (7, stored_response(5)))]);
            assert_eq!(
                consumer
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .prefetch_retained_bytes(),
                5
            );
        })
        .await
        .unwrap();
    }

    #[test]
    fn a_full_window_releases_the_blocking_pool() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let queue = Responses::start(
                    (0..=WINDOW)
                        .map(|index| (index, stored_response(1)))
                        .collect(),
                )
                .unwrap();
                let deadline = std::time::Duration::from_secs(5);
                tokio::time::timeout(deadline, async {
                    while queue.shared.state.lock().unwrap().ready.len() != WINDOW {
                        tokio::task::yield_now().await;
                    }
                    tokio::task::spawn_blocking(|| ()).await.unwrap();
                })
                .await
                .unwrap();
            });
    }

    #[test]
    fn prefetch_window_discards_late_entries_and_bounds_retained_bytes() {
        let response = stored_response(MAX_BYTES);
        let mut window = Window::default();
        window.insert(1, response.load(MAX_BYTES).unwrap().unwrap());
        window.insert(2, response.load(MAX_BYTES).unwrap().unwrap());
        assert_eq!(window.ready.len(), 1);
        assert_eq!(window.bytes, MAX_BYTES);
        window.advance(3);
        assert_eq!(window.bytes, 0);
        window.insert(1, response.load(MAX_BYTES).unwrap().unwrap());
        assert!(window.ready.is_empty());
    }
}
