//! Retain one contiguous, independent run of message outputs until wire acceptance.
use std::sync::Arc;

use anyhow::{Result, ensure};
use tokio::time::Duration;

use super::SequenceRuntime;
use crate::{EventKind, SequenceScheduler, SlotState};

const EVENTS_PER_MESSAGE: usize = 3;
const MAX_MESSAGES: usize = 32;

impl SequenceRuntime {
    /// Return a bounded contiguous run of complete standalone message spans.
    /// The live owner still verifies subscription identity and frame eligibility.
    pub fn message_batch_candidates(&self, limit: usize) -> Vec<u64> {
        if !self.supports_message_batches() || limit < 2 {
            return Vec::new();
        }
        let state = self.state.lock().expect("sequence runtime poisoned");
        if state.message_batch_reserved || state.scheduler.failed() {
            return Vec::new();
        }
        let mut candidates = state.scheduler.batch_dependencies(limit).peekable();
        let Some(first) = candidates.next().filter(|_| candidates.peek().is_some()) else {
            return Vec::new();
        };
        std::iter::once(first).chain(candidates).collect()
    }

    pub fn reserve_message_batch(self: &Arc<Self>, dependencies: &[u64]) -> Result<MessageBatch> {
        ensure!(
            self.supports_message_batches(),
            "sequence does not allow message batches"
        );
        ensure!(
            (2..=MAX_MESSAGES).contains(&dependencies.len()),
            "message batch exceeds its bounds"
        );
        let mut state = self.state.lock().expect("sequence runtime poisoned");
        ensure!(
            !state.message_batch_reserved && !state.scheduler.failed(),
            "message batch frontier is unavailable"
        );
        ensure!(
            state
                .scheduler
                .batch_dependencies(dependencies.len())
                .eq(dependencies.iter().copied()),
            "message batch crosses the recorded frontier or a barrier"
        );
        state.message_batch_reserved = true;
        Ok(MessageBatch {
            runtime: self.clone(),
            dependencies: dependencies.to_vec(),
            armed: true,
        })
    }

    fn supports_message_batches(&self) -> bool {
        self.session_timing && self.fast_gap_cap == Some(Duration::ZERO)
    }
}

impl SequenceScheduler {
    fn batch_dependencies(&self, limit: usize) -> impl Iterator<Item = u64> + '_ {
        self.plan.events[self.cursor..]
            .as_chunks::<EVENTS_PER_MESSAGE>()
            .0
            .iter()
            .take(limit.min(MAX_MESSAGES))
            .enumerate()
            .map_while(|(ordinal, events @ [message, start, end])| {
                let receipt = self.cursor + ordinal * EVENTS_PER_MESSAGE + 2;
                (message.source.kind == EventKind::Message
                    && start.source.kind == EventKind::ResponseEndStarted
                    && end.source.kind == EventKind::ResponseEnd
                    && message.slot == start.slot
                    && start.slot == end.slot
                    && start.receipt_cursor == receipt
                    && self.slots[message.slot] == SlotState::Available
                    && !self.pending_delivery.contains_key(&receipt)
                    && !events
                        .iter()
                        .any(|event| self.event_is_gated(event.source.sequence)))
                .then_some(message.source.dependency_sequence)
            })
    }

    fn publish_message_prefix(&mut self, count: usize) {
        let end = self.cursor + count * EVENTS_PER_MESSAGE;
        let (frames, remainder) =
            self.plan.events[self.cursor..end].as_chunks::<EVENTS_PER_MESSAGE>();
        debug_assert!(remainder.is_empty());
        for [message, ..] in frames {
            self.slots[message.slot] = SlotState::Consumed;
        }
        self.cursor = end;
        self.drain_receipts();
    }
}

/// Exclusive frontier ownership while the connection writes a single vector
/// of frames. A dropped writer must never release potentially written bytes.
pub struct MessageBatch {
    runtime: Arc<SequenceRuntime>,
    dependencies: Vec<u64>,
    armed: bool,
}

impl MessageBatch {
    /// Publish only full frames accepted by the writer. Zero releases the
    /// reservation cleanly if the writer has never exposed any bytes.
    pub fn publish_prefix(mut self, count: usize) -> Result<PublishedMessageBatch> {
        ensure!(
            count <= self.dependencies.len(),
            "message receipt exceeds its reservation"
        );
        let mut state = self
            .runtime
            .state
            .lock()
            .expect("sequence runtime poisoned");
        ensure!(
            state.message_batch_reserved && !state.scheduler.failed(),
            "message reservation is no longer live"
        );
        state.scheduler.publish_message_prefix(count);
        if count != 0 {
            state.record_progress();
        }
        state.message_batch_reserved = false;
        let notifications = state.notifications(true);
        drop(state);
        self.armed = false;
        self.runtime.notify(notifications);
        self.dependencies.truncate(count);
        Ok(PublishedMessageBatch {
            runtime: self.runtime.clone(),
            dependencies: std::mem::take(&mut self.dependencies),
        })
    }

    pub fn abort(self) {
        drop(self);
    }
}

impl Drop for MessageBatch {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self
                .runtime
                .state
                .lock()
                .expect("sequence runtime poisoned");
            state.message_batch_reserved = false;
            if !state.scheduler.failed() {
                state.scheduler.abort();
                let notifications = state.notifications(false);
                drop(state);
                self.runtime.notify(notifications);
            }
        }
    }
}

/// Proof that the sequence consumed an accepted prefix under its reservation.
pub struct PublishedMessageBatch {
    runtime: Arc<SequenceRuntime>,
    dependencies: Vec<u64>,
}

impl PublishedMessageBatch {
    pub fn dependencies(&self) -> &[u64] {
        &self.dependencies
    }

    pub(crate) fn belongs_to(&self, runtime: &SequenceRuntime) -> bool {
        std::ptr::eq(self.runtime.as_ref(), runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SequencePlan, SourceEvent};

    fn event(sequence: u64, dependency_sequence: u64, kind: EventKind) -> SourceEvent {
        SourceEvent {
            sequence,
            dependency_sequence,
            kind,
            offset_micros: sequence,
        }
    }

    fn message(sequence: u64) -> [SourceEvent; 3] {
        [
            event(sequence, sequence, EventKind::Message),
            event(sequence + 2, sequence, EventKind::ResponseEndStarted),
            event(sequence + 3, sequence, EventKind::ResponseEnd),
        ]
    }

    fn session(
        events: impl IntoIterator<Item = SourceEvent>,
        gates: impl IntoIterator<Item = u64>,
    ) -> Arc<SequenceRuntime> {
        SequenceRuntime::with_session_timing(
            SequencePlan::compile(events).unwrap(),
            Some(Duration::ZERO),
            gates,
        )
    }

    #[test]
    fn publishes_only_a_wire_accepted_prefix_and_notifies_once() {
        let events = message(10)
            .into_iter()
            .chain(message(20))
            .chain(message(30));
        let runtime = session(events, []);
        assert_eq!(runtime.message_batch_candidates(32), [10, 20, 30]);
        let progress = runtime.subscribe();
        let batch = runtime.reserve_message_batch(&[10, 20, 30]).unwrap();
        assert_eq!(*progress.borrow(), 0);
        assert!(runtime.admissible_message().is_none());
        assert!(runtime.admit(10).is_err());
        assert!(runtime.reserve_message_batch(&[10, 20]).is_err());
        assert_eq!(runtime.progress().matched, 0);

        let receipt = batch.publish_prefix(1).unwrap();
        assert_eq!(receipt.dependencies(), [10]);
        assert_eq!(*progress.borrow(), 1);
        assert_eq!(runtime.progress().matched, 3);
        assert_eq!(runtime.message_batch_candidates(32), [20, 30]);

        let batch = runtime.reserve_message_batch(&[20, 30]).unwrap();
        let receipt = batch.publish_prefix(2).unwrap();
        assert_eq!(receipt.dependencies(), [20, 30]);
        assert_eq!(*progress.borrow(), 2);
        assert!(runtime.complete());
    }

    #[test]
    fn stops_before_an_interleaving_event_or_timer_gate() {
        let events = message(10)
            .into_iter()
            .chain(message(20))
            .chain([event(25, 0, EventKind::PrimaryRequest)])
            .chain(message(30))
            .chain(message(40));
        let runtime = session(events.clone(), []);
        assert_eq!(runtime.message_batch_candidates(32), [10, 20]);
        assert!(runtime.reserve_message_batch(&[10, 20, 30]).is_err());

        let gated = session(events, [23]);
        assert!(gated.message_batch_candidates(32).is_empty());
        assert!(gated.reserve_message_batch(&[10, 20]).is_err());
        let realtime = SequenceRuntime::with_session_timing(
            SequencePlan::compile(message(10).into_iter().chain(message(20))).unwrap(),
            None,
            [],
        );
        assert!(realtime.message_batch_candidates(32).is_empty());
    }

    #[test]
    fn releases_an_unwritten_reservation_but_aborts_on_dropped_writer() {
        let runtime = session(message(10).into_iter().chain(message(20)), []);
        let batch = runtime.reserve_message_batch(&[10, 20]).unwrap();
        assert!(batch.publish_prefix(0).unwrap().dependencies().is_empty());
        assert_eq!(runtime.admissible_message().unwrap().sequence, 10);
        let batch = runtime.reserve_message_batch(&[10, 20]).unwrap();
        drop(batch);
        assert!(runtime.failed());
        assert_eq!(runtime.progress().matched, 0);
    }

    #[tokio::test]
    async fn allows_a_preceding_write_to_publish_its_later_receipt() {
        let runtime = session(
            [
                event(1, 1, EventKind::Request),
                event(3, 1, EventKind::ResponseEndStarted),
            ]
            .into_iter()
            .chain(message(10))
            .chain(message(20))
            .chain([event(31, 1, EventKind::ResponseEnd)]),
            [],
        );
        let first = runtime.admit(1).unwrap();
        first
            .wait_delivery(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let batch = runtime.reserve_message_batch(&[10, 20]).unwrap();
        first.publish().unwrap();
        assert!(!first.complete());
        batch.publish_prefix(2).unwrap();
        assert!(first.complete());
        assert!(runtime.complete());
    }
}
