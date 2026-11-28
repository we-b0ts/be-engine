//! Read ahead immutable Session responses without admitting any events.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};

use crate::replay::native::{LoadedResponse, ResponsePreparation};
use anyhow::{Result, ensure};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};

const WINDOW: usize = 256;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const READ_BATCH: usize = 32;
const PARALLEL_BATCHES: usize = 3;

type ScheduledResponse = (usize, ResponsePreparation);

pub(in crate::replay) struct Responses {
    ordinals: HashMap<usize, usize>,
    shared: Arc<Shared>,
    rolling_workers: Option<Arc<Semaphore>>,
}

pub(in crate::replay) struct CloseOnDrop(Arc<Shared>);

#[derive(Default)]
struct Shared {
    state: Mutex<Window>,
    refill: Notify,
    wait_micros: AtomicU64,
    packets_used: AtomicUsize,
    packet_batches: AtomicUsize,
    packet_batch_frames: AtomicUsize,
    packet_batch_writes: AtomicUsize,
}

#[derive(Default)]
struct Window {
    first: usize,
    // Absence means pending. A completed entry without a response uses the
    // normal delivery path, which also reports any load or Source error.
    completed: BTreeMap<usize, Option<LoadedResponse>>,
    // A blocked take advances first to its requested ordinal. Advancing again
    // releases the earlier waiter, which can then load on demand.
    head_waiter: Option<Arc<Notify>>,
    // Earliest window start that fits the producer's next batch.
    refill_at: Option<usize>,
    bytes: usize,
    peak_bytes: usize,
    hits: usize,
    prepared_hits: usize,
    delivery_prepared_hits: usize,
    packet_prepared_hits: usize,
    compact_packet_hits: usize,
    misses: usize,
    waits: usize,
    producer_finished: bool,
    closed: bool,
    rolling: RollingOrdinals,
}

#[derive(Default)]
struct RollingOrdinals {
    next: usize,
    indices: HashMap<usize, usize>,
    order: VecDeque<(usize, usize)>,
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
        Some(Arc::new(Self {
            ordinals,
            shared,
            rolling_workers: None,
        }))
    }

    pub(in crate::replay) fn rolling() -> Arc<Self> {
        Arc::new(Self {
            ordinals: HashMap::new(),
            shared: Arc::new(Shared::default()),
            rolling_workers: Some(Arc::new(Semaphore::new(PARALLEL_BATCHES))),
        })
    }

    pub(in crate::replay) fn submit(&self, responses: Vec<ScheduledResponse>) {
        let Some(workers) = &self.rolling_workers else {
            return;
        };
        let mut responses = responses.into_iter().peekable();
        while responses.peek().is_some() {
            let Ok(permit) = workers.clone().try_acquire_owned() else {
                return;
            };
            let batch = {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .expect("response prefetch poisoned");
                if state.closed {
                    return;
                }
                let available = (WINDOW - state.rolling.order.len()).min(READ_BATCH);
                responses
                    .by_ref()
                    .take(available)
                    .filter_map(|(index, response)| {
                        if state.rolling.indices.contains_key(&index) {
                            return None;
                        }
                        let ordinal = state.rolling.next;
                        state.rolling.next += 1;
                        state.rolling.indices.insert(index, ordinal);
                        state.rolling.order.push_back((ordinal, index));
                        Some((ordinal, (index, response)))
                    })
                    .collect::<Vec<_>>()
            };
            if batch.is_empty() {
                return;
            }
            let shared = self.shared.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                load_batch(&shared, batch);
            });
        }
    }

    fn ordinal(&self, state: &Window, index: usize) -> Option<usize> {
        if self.rolling_workers.is_some() {
            state.rolling.indices.get(&index).copied()
        } else {
            self.ordinals.get(&index).copied()
        }
    }

    pub(in crate::replay) async fn take(&self, index: usize) -> Result<Option<LoadedResponse>> {
        let ordinal = if self.rolling_workers.is_some() {
            let state = self
                .shared
                .state
                .lock()
                .expect("response prefetch poisoned");
            self.ordinal(&state, index)
        } else {
            self.ordinals.get(&index).copied()
        };
        let Some(ordinal) = ordinal else {
            return Ok(None);
        };
        let mut waiting = false;
        loop {
            let (response, available, (head, refill)) = {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .expect("response prefetch poisoned");
                ensure!(
                    !state.closed,
                    "Session ended before prefetched response was delivered"
                );
                let completed = state.remove(ordinal);
                let pending =
                    completed.is_none() && ordinal >= state.first && !state.producer_finished;
                let response = completed.flatten();
                if pending {
                    if !waiting {
                        state.waits += 1;
                        waiting = true;
                    }
                } else if let Some(response) = &response {
                    state.record_hit(response);
                } else {
                    state.misses += 1;
                }
                let change = state.advance(ordinal + usize::from(!pending));
                let available = pending.then(|| {
                    // Register under the Window lock. notify_waiters records the
                    // generation before this future is polled.
                    state
                        .head_waiter
                        .get_or_insert_with(Default::default)
                        .clone()
                        .notified_owned()
                });
                (response, available, change)
            };
            self.shared.notify_advance(head, refill);
            match available {
                Some(available) => {
                    let started = Instant::now();
                    available.await;
                    self.shared
                        .wait_micros
                        .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
                }
                None => return Ok(response),
            }
        }
    }

    /// Take an already loaded, consecutive prefix when it contains at least
    /// two acceptable responses. A shorter prefix stays available to `take`.
    pub(in crate::replay) fn take_ready_batch<T>(
        &self,
        indices: impl IntoIterator<Item = usize>,
        mut accept: impl FnMut(usize, &LoadedResponse) -> Option<T>,
    ) -> Vec<(usize, LoadedResponse, T)> {
        let (batch, (head, refill)) = {
            let mut state = self
                .shared
                .state
                .lock()
                .expect("response prefetch poisoned");
            if state.closed {
                return Vec::new();
            }
            let mut accepted = Vec::new();
            let mut next = None;
            for index in indices.into_iter().take(READ_BATCH) {
                let Some(ordinal) = self.ordinal(&state, index) else {
                    break;
                };
                if next.is_some_and(|next| ordinal != next) {
                    break;
                }
                let Some(Some(response)) = state.completed.get(&ordinal) else {
                    break;
                };
                let Some(value) = accept(index, response) else {
                    break;
                };
                accepted.push((index, ordinal, value));
                next = Some(ordinal + 1);
            }
            if accepted.len() < 2 {
                return Vec::new();
            }
            let batch = accepted
                .into_iter()
                .map(|(index, ordinal, value)| {
                    let response = state
                        .remove(ordinal)
                        .flatten()
                        .expect("checked under prefetch lock");
                    state.record_hit(&response);
                    (index, response, value)
                })
                .collect();
            let change = state.advance(next.expect("accepted prefetch prefix has an end"));
            (batch, change)
        };
        self.shared.notify_advance(head, refill);
        batch
    }

    pub(in crate::replay) fn close(&self) {
        self.shared.close();
    }

    pub(in crate::replay) fn record_prefetched_packet_use(&self) {
        self.shared.packets_used.fetch_add(1, Ordering::Relaxed);
    }

    pub(in crate::replay) fn record_packet_batch(&self, frames: usize, writes: usize) {
        self.shared
            .packets_used
            .fetch_add(frames, Ordering::Relaxed);
        self.shared.packet_batches.fetch_add(1, Ordering::Relaxed);
        self.shared
            .packet_batch_frames
            .fetch_add(frames, Ordering::Relaxed);
        self.shared
            .packet_batch_writes
            .fetch_add(writes, Ordering::Relaxed);
    }

    pub(in crate::replay) fn close_on_drop(&self) -> CloseOnDrop {
        CloseOnDrop(self.shared.clone())
    }
}

impl Window {
    fn record_hit(&mut self, response: &LoadedResponse) {
        self.hits += 1;
        self.prepared_hits += usize::from(response.has_source_preparation());
        self.delivery_prepared_hits += usize::from(response.has_prepared_delivery());
        self.packet_prepared_hits += usize::from(response.has_prefetched_packet());
        self.compact_packet_hits += usize::from(response.has_compact_packet());
    }

    fn remove(&mut self, ordinal: usize) -> Option<Option<LoadedResponse>> {
        let response = self.completed.remove(&ordinal)?;
        self.release(response.as_ref());
        Some(response)
    }

    fn release(&mut self, response: Option<&LoadedResponse>) {
        if let Some(response) = response {
            self.bytes -= response.prefetch_retained_bytes();
        }
    }

    fn advance(&mut self, first: usize) -> (Option<Arc<Notify>>, bool) {
        if first <= self.first {
            return (None, false);
        }
        // Output starts are ordered, but different connection tasks can reach
        // the buffer in a different order. Earlier deliveries can load on demand.
        self.first = first;
        while self
            .rolling
            .order
            .front()
            .is_some_and(|(ordinal, _)| *ordinal < self.first)
        {
            let (_, index) = self
                .rolling
                .order
                .pop_front()
                .expect("old response ordinal");
            self.rolling.indices.remove(&index);
        }
        while self
            .completed
            .first_key_value()
            .is_some_and(|(queued, _)| *queued < self.first)
        {
            let (_, response) = self
                .completed
                .pop_first()
                .expect("stale prefetched response");
            self.release(response.as_ref());
        }
        let refill = self
            .refill_at
            .is_some_and(|first| self.first >= first && self.bytes < MAX_BYTES);
        if refill {
            self.refill_at = None;
        }
        (self.head_waiter.take(), refill)
    }

    fn complete(
        &mut self,
        ordinal: usize,
        response: Option<LoadedResponse>,
    ) -> Option<Arc<Notify>> {
        if self.closed || self.producer_finished || ordinal < self.first {
            return None;
        }
        let response = response
            .filter(|response| response.prefetch_retained_bytes() <= MAX_BYTES - self.bytes);
        self.bytes += response
            .as_ref()
            .map_or(0, LoadedResponse::prefetch_retained_bytes);
        self.peak_bytes = self.peak_bytes.max(self.bytes);
        self.completed.insert(ordinal, response);
        if ordinal == self.first {
            self.head_waiter.take()
        } else {
            None
        }
    }
}

async fn produce(shared: Arc<Shared>, responses: Vec<ScheduledResponse>) {
    let mut responses = responses.into_iter().enumerate().peekable();
    let mut workers = JoinSet::new();
    loop {
        let refill = shared.refill.notified();
        let batch_size = {
            let mut state = shared.state.lock().expect("response prefetch poisoned");
            if state.closed {
                return;
            }
            while responses
                .peek()
                .is_some_and(|(ordinal, _)| *ordinal < state.first)
            {
                responses.next();
            }
            let next = responses.len().min(READ_BATCH);
            state.refill_at = None;
            match responses.peek() {
                Some((ordinal, _)) if workers.len() < PARALLEL_BATCHES => {
                    let first = (*ordinal + next).saturating_sub(WINDOW);
                    if state.first >= first && state.bytes < MAX_BYTES {
                        next
                    } else {
                        state.refill_at = Some(first);
                        0
                    }
                }
                _ => 0,
            }
        };
        if batch_size > 0 {
            let batch = responses.by_ref().take(batch_size).collect();
            let worker = shared.clone();
            workers.spawn_blocking(move || load_batch(&worker, batch));
            continue;
        }
        if responses.peek().is_none() && workers.is_empty() {
            break;
        }
        tokio::select! {
            () = refill => {}
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::debug!(%error, "Session response prefetch worker stopped");
                    break;
                }
            }
        }
    }
    let head = {
        let mut state = shared.state.lock().expect("response prefetch poisoned");
        state.producer_finished = true;
        state.head_waiter.take()
    };
    if let Some(head) = head {
        head.notify_waiters();
    }
}

fn load_batch(shared: &Shared, batch: Vec<(usize, ScheduledResponse)>) {
    for (ordinal, (_, response)) in batch {
        let available_bytes = {
            let state = shared.state.lock().expect("response prefetch poisoned");
            if state.closed || state.producer_finished {
                return;
            }
            if ordinal < state.first {
                continue;
            }
            MAX_BYTES - state.bytes
        };
        // Keep failures and responses without a memory estimate on the normal
        // delivery path. Each worker can hold one transient decoded response.
        // Completions contend only when admitted into the shared byte budget.
        let response = if available_bytes > 0 {
            response.load(available_bytes).ok().flatten()
        } else {
            None
        };
        let head = shared
            .state
            .lock()
            .expect("response prefetch poisoned")
            .complete(ordinal, response);
        if let Some(head) = head {
            head.notify_waiters();
        }
    }
}

impl Drop for Responses {
    fn drop(&mut self) {
        let (
            hits,
            prepared_hits,
            delivery_prepared_hits,
            packet_prepared_hits,
            compact_packet_hits,
            misses,
            waits,
            peak_bytes,
        ) = self.shared.close();
        tracing::info!(
            hits,
            prepared_hits,
            delivery_prepared_hits,
            packet_prepared_hits,
            compact_packet_hits,
            packets_used = self.shared.packets_used.load(Ordering::Relaxed),
            packet_batches = self.shared.packet_batches.load(Ordering::Relaxed),
            packet_batch_frames = self.shared.packet_batch_frames.load(Ordering::Relaxed),
            packet_batch_writes = self.shared.packet_batch_writes.load(Ordering::Relaxed),
            misses,
            waits,
            wait_micros = self.shared.wait_micros.load(Ordering::Relaxed),
            parallel_batches = PARALLEL_BATCHES,
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
    fn notify_advance(&self, head: Option<Arc<Notify>>, refill: bool) {
        if let Some(head) = head {
            head.notify_waiters();
        }
        if refill {
            self.refill.notify_one();
        }
    }

    fn close(&self) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
        let mut state = self.state.lock().expect("response prefetch poisoned");
        state.closed = true;
        state.completed.clear();
        state.rolling = RollingOrdinals::default();
        state.bytes = 0;
        let head = state.head_waiter.take();
        let stats = (
            state.hits,
            state.prepared_hits,
            state.delivery_prepared_hits,
            state.packet_prepared_hits,
            state.compact_packet_hits,
            state.misses,
            state.waits,
            state.peak_bytes,
        );
        drop(state);
        self.refill.notify_one();
        if let Some(head) = head {
            head.notify_waiters();
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use hyper::body::Bytes;
    use serde_json::Value;
    use std::{sync::Condvar, time::Duration};
    use traffic_protocol::message::{
        MessageEncoder, ProjectedMessage, ProtocolMessage, StoredMessage,
    };

    struct TestResponse {
        bytes: usize,
        stored: bool,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    fn stored_response(bytes: usize) -> ResponsePreparation {
        ResponsePreparation::decode_only(Arc::new(TestResponse {
            bytes,
            stored: true,
            gate: None,
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
            if let Some(gate) = &self.gate {
                let (released, changed) = gate.as_ref();
                let (released, _) = changed
                    .wait_timeout_while(released.lock().unwrap(), Duration::from_secs(5), |open| {
                        !*open
                    })
                    .unwrap();
                ensure!(*released, "Test prefetch response was not released");
            }
            Ok(Arc::new(Self {
                bytes: self.bytes,
                stored: false,
                gate: None,
            }))
        }
    }

    #[tokio::test]
    async fn prefetch_returns_the_prepared_response_by_exchange_index() {
        let queue =
            Responses::start(vec![(9, stored_response(3)), (7, stored_response(5))]).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while queue.shared.state.lock().unwrap().completed.len() < 2 {
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

    #[test]
    fn ready_batch_leaves_a_single_candidate_for_normal_delivery() {
        let shared = Arc::new(Shared::default());
        let queue = Responses {
            ordinals: HashMap::from([(7, 0), (9, 1), (11, 2), (13, 3)]),
            shared: shared.clone(),
            rolling_workers: None,
        };
        load_batch(
            &shared,
            vec![
                (0, (7, stored_response(3))),
                (1, (9, stored_response(5))),
                (3, (13, stored_response(8))),
            ],
        );

        let batch = queue.take_ready_batch([7, 9], |index, _| (index == 7).then_some(()));
        assert!(batch.is_empty());
        {
            let state = shared.state.lock().unwrap();
            assert_eq!(state.first, 0);
            assert_eq!(state.hits, 0);
            assert_eq!(state.bytes, 16);
        }

        let batch = queue.take_ready_batch([7, 9, 13], |_, response| {
            Some(response.prefetch_retained_bytes())
        });
        let entries: Vec<_> = batch
            .into_iter()
            .map(|(index, _, bytes)| (index, bytes))
            .collect();
        assert_eq!(entries, [(7, 3), (9, 5)]);
        assert!(queue.take_ready_batch([11, 13], |_, _| Some(())).is_empty());
        let state = shared.state.lock().unwrap();
        assert_eq!(state.first, 2);
        assert_eq!(state.hits, 2);
        assert_eq!(state.waits, 0);
        assert_eq!(state.bytes, 8);
        assert!(state.completed[&3].is_some());
    }

    #[tokio::test]
    async fn an_empty_window_waits_for_the_requested_response() {
        let shared = Arc::new(Shared::default());
        let queue = Arc::new(Responses {
            ordinals: HashMap::from([(7, 0)]),
            shared: shared.clone(),
            rolling_workers: None,
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

    #[tokio::test]
    async fn advancing_and_closing_wake_blocked_consumers() {
        let shared = Arc::new(Shared::default());
        let queue = Arc::new(Responses {
            ordinals: HashMap::from([(7, 0), (9, 1)]),
            shared: shared.clone(),
            rolling_workers: None,
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let earlier = tokio::spawn({
                let queue = queue.clone();
                async move { queue.take(7).await }
            });
            while shared.state.lock().unwrap().waits < 1 {
                tokio::task::yield_now().await;
            }
            let later = tokio::spawn({
                let queue = queue.clone();
                async move { queue.take(9).await }
            });
            assert!(earlier.await.unwrap().unwrap().is_none());
            assert!(!later.is_finished());
            queue.close();
            assert!(later.await.unwrap().is_err());
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
                    while queue.shared.state.lock().unwrap().completed.len() != WINDOW {
                        tokio::task::yield_now().await;
                    }
                    tokio::task::spawn_blocking(|| ()).await.unwrap();
                    assert!(queue.take(0).await.unwrap().is_some());
                    while !queue
                        .shared
                        .state
                        .lock()
                        .unwrap()
                        .completed
                        .contains_key(&WINDOW)
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            });
    }

    #[tokio::test]
    async fn another_batch_can_finish_while_the_head_response_is_pending() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let head = ResponsePreparation::decode_only(Arc::new(TestResponse {
            bytes: 5,
            stored: true,
            gate: Some(gate.clone()),
        }));
        let queue = Responses::start(
            std::iter::once((0, head))
                .chain((1..=READ_BATCH).map(|index| (index, stored_response(1))))
                .collect(),
        )
        .unwrap();
        let consumer = tokio::spawn({
            let queue = queue.clone();
            async move { queue.take(0).await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                {
                    let state = queue.shared.state.lock().unwrap();
                    if state.waits > 0 && state.completed.contains_key(&READ_BATCH) {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
            assert!(!consumer.is_finished());
            *gate.0.lock().unwrap() = true;
            gate.1.notify_one();
            let loaded = consumer.await.unwrap().unwrap().unwrap();
            assert_eq!(loaded.prefetch_retained_bytes(), 5);
        })
        .await
        .unwrap();
    }

    #[test]
    fn prefetch_window_discards_late_entries_and_bounds_retained_bytes() {
        let response = stored_response(MAX_BYTES);
        let mut window = Window::default();
        assert!(
            window
                .complete(1, response.load(MAX_BYTES).unwrap())
                .is_none()
        );
        assert!(
            window
                .complete(2, response.load(MAX_BYTES).unwrap())
                .is_none()
        );
        assert!(window.completed[&1].is_some());
        assert!(window.completed[&2].is_none());
        assert_eq!(window.bytes, MAX_BYTES);
        window.advance(3);
        assert_eq!(window.bytes, 0);
        assert!(
            window
                .complete(1, response.load(MAX_BYTES).unwrap())
                .is_none()
        );
        assert!(window.completed.is_empty());
    }

    #[test]
    fn only_the_requested_response_takes_the_current_waiter() {
        let waiter = Arc::new(Notify::new());
        let mut window = Window {
            first: 1,
            head_waiter: Some(waiter.clone()),
            ..Window::default()
        };
        assert!(window.complete(2, None).is_none());
        assert!(Arc::ptr_eq(&window.complete(1, None).unwrap(), &waiter));
    }

    #[test]
    fn refill_wakes_once_when_the_batch_fits_both_budgets() {
        let mut window = Window {
            refill_at: Some(READ_BATCH),
            ..Window::default()
        };
        let response = stored_response(MAX_BYTES).load(MAX_BYTES).unwrap();
        assert!(window.complete(READ_BATCH, response).is_none());
        assert!(!window.advance(READ_BATCH - 1).1);
        assert!(!window.advance(READ_BATCH).1);
        assert!(window.remove(READ_BATCH).is_some());
        assert!(window.advance(READ_BATCH + 1).1);
        assert!(!window.advance(READ_BATCH + 2).1);
    }
}
