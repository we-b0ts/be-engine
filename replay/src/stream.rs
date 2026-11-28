//! Ordered schedule entries and active slots for whole-session Replay.
use std::collections::{HashMap, VecDeque};

use anyhow::{Result, ensure};

use crate::{SequenceScheduler, SlotState, SourceEvent};

#[derive(Debug, Clone, Copy)]
pub struct StreamEvent {
    pub source: SourceEvent,
    /// The earlier start of a separately recorded delivery receipt.
    pub receipt_start: Option<u64>,
}

#[derive(Clone, Copy)]
pub(crate) struct ScheduledEvent {
    pub(crate) source: SourceEvent,
    pub(crate) receipt_start: Option<u64>,
    // Frozen plans additionally provide the exact receipt Source event to a
    // wire writer. Streaming reserves a stable start identity immediately.
    pub(crate) receipt: Option<SourceEvent>,
}

impl ScheduledEvent {
    pub(crate) fn delivery_id(self) -> u64 {
        self.receipt_start.unwrap_or(self.source.sequence)
    }
}

#[derive(Debug, Default)]
pub(crate) struct StreamWindow {
    events: VecDeque<StreamEvent>,
    previous: Option<SourceEvent>,
    appended: Option<SourceEvent>,
    total: Option<usize>,
    slots: HashMap<u64, StreamSlot>,
    output_starts: HashMap<u64, SourceEvent>,
    open: usize,
}

#[derive(Debug)]
struct StreamSlot {
    status: SlotState,
    recorded_terminal: bool,
    open_outputs: usize,
}

impl StreamWindow {
    pub(crate) fn previous(&self) -> Option<SourceEvent> {
        self.previous
    }

    fn push(&mut self, entry: StreamEvent) -> Result<()> {
        let source = entry.source;
        ensure!(
            source.sequence != 0
                && self.appended.is_none_or(|last| {
                    last.sequence < source.sequence && last.offset_micros <= source.offset_micros
                }),
            "unordered Session Source sequence {}",
            source.sequence
        );
        if let Some(start) = entry.receipt_start {
            ensure!(
                self.output_starts.get(&start).is_some_and(|output| {
                    output.dependency_sequence == source.dependency_sequence
                        && output.kind.delivered() == source.kind
                }),
                "Source receipt at sequence {} disagrees with its output start",
                source.sequence
            );
        }
        let dependency = source.dependency_sequence;
        if source.kind.is_session_driver_event() {
            ensure!(dependency == 0, "driver event owns a dependency");
        } else if source.kind.is_admission() {
            ensure!(
                dependency == source.sequence && !self.slots.contains_key(&dependency),
                "invalid Source dependency admission at sequence {}",
                source.sequence
            );
            self.slots.insert(
                dependency,
                StreamSlot {
                    status: SlotState::Available,
                    recorded_terminal: false,
                    open_outputs: 0,
                },
            );
            self.open += 1;
        } else {
            let slot = self
                .slots
                .get_mut(&dependency)
                .filter(|slot| !slot.recorded_terminal)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Source response has no open request at sequence {}",
                        source.sequence
                    )
                })?;
            let open_outputs = slot.open_outputs + usize::from(source.kind.is_started());
            let open_outputs = open_outputs
                .checked_sub(usize::from(entry.receipt_start.is_some()))
                .ok_or_else(|| anyhow::anyhow!("Source output receipt has no admitted start"))?;
            if source.kind.is_terminal() {
                ensure!(
                    open_outputs == 0,
                    "Source dependency terminated with outstanding outputs"
                );
                self.open -= 1;
                slot.recorded_terminal = true;
            }
            slot.open_outputs = open_outputs;
            if source.kind.is_started() {
                self.output_starts.insert(source.sequence, source);
            } else if let Some(start) = entry.receipt_start {
                self.output_starts.remove(&start);
            }
        }
        self.appended = Some(source);
        self.events.push_back(entry);
        Ok(())
    }
}

impl SequenceScheduler {
    pub(crate) fn streaming(plan: std::sync::Arc<crate::SequencePlan>) -> Self {
        let mut scheduler = Self::new(plan);
        scheduler.stream = Some(StreamWindow::default());
        scheduler
    }

    pub(crate) fn push_stream(&mut self, entries: Vec<StreamEvent>, finished: bool) -> Result<()> {
        let result = (|| {
            let stream = self.stream.as_mut().expect("streaming Session scheduler");
            ensure!(
                stream.total.is_none() && !self.failed,
                "Session schedule has ended"
            );
            for entry in entries {
                stream.push(entry)?;
            }
            if finished {
                ensure!(
                    stream.open == 0 && stream.output_starts.is_empty(),
                    "Session schedule is missing a dependency terminal or output receipt"
                );
                stream.total = Some(self.cursor + stream.events.len());
            }
            Ok(())
        })();
        self.drain_receipts();
        result
    }

    pub(crate) fn event_at(&self, cursor: usize) -> Option<ScheduledEvent> {
        if let Some(stream) = &self.stream {
            let event = stream.events.get(cursor.checked_sub(self.cursor)?)?;
            return Some(ScheduledEvent {
                source: event.source,
                receipt_start: event.receipt_start,
                receipt: None,
            });
        }
        let event = self.plan.events.get(cursor)?;
        Some(ScheduledEvent {
            source: event.source,
            receipt_start: event.receipt_start,
            receipt: event
                .source
                .kind
                .is_started()
                .then(|| self.plan.events[event.receipt_cursor].source),
        })
    }

    pub(crate) fn slot_status(&self, dependency: u64) -> Option<SlotState> {
        if let Some(stream) = &self.stream {
            return stream.slots.get(&dependency).map(|slot| slot.status);
        }
        self.plan
            .slots
            .get(&dependency)
            .map(|slot| self.slots[*slot])
    }

    pub(crate) fn set_slot(&mut self, dependency: u64, status: SlotState) {
        if let Some(stream) = &mut self.stream {
            if status == SlotState::Consumed {
                stream.slots.remove(&dependency);
            } else {
                stream
                    .slots
                    .get_mut(&dependency)
                    .expect("active Session slot")
                    .status = status;
            }
        } else {
            self.slots[self.plan.slots[&dependency]] = status;
        }
    }

    pub(crate) fn advance(&mut self) {
        if let Some(stream) = &mut self.stream {
            stream.previous = Some(
                stream
                    .events
                    .pop_front()
                    .expect("active Session event")
                    .source,
            );
        }
        self.cursor += 1;
    }

    pub(crate) fn total(&self) -> Option<usize> {
        self.stream
            .as_ref()
            .map_or_else(|| Some(self.plan.event_count()), |stream| stream.total)
    }

    pub(crate) fn buffered(&self) -> usize {
        self.stream.as_ref().map_or_else(
            || self.plan.event_count() - self.cursor,
            |stream| stream.events.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, SequenceRuntime};
    use tokio::time::{Duration, Instant};

    fn event(sequence: u64, dependency_sequence: u64, kind: EventKind) -> StreamEvent {
        StreamEvent {
            source: SourceEvent {
                sequence,
                dependency_sequence,
                kind,
                offset_micros: sequence,
            },
            receipt_start: None,
        }
    }

    #[tokio::test]
    async fn streaming_output_can_finish_before_its_receipt_enters_the_window() -> Result<()> {
        let runtime = SequenceRuntime::streaming_session(Some(Duration::ZERO), []);
        let request = event(1, 1, EventKind::Request);
        let start = event(2, 1, EventKind::ResponseEndStarted);
        let ready = event(3, 0, EventKind::SessionReady);
        runtime.push_stream(vec![request, start, ready], false)?;
        let claim = runtime.admit(1)?;
        claim
            .wait_delivery(Instant::now() + Duration::from_secs(1))
            .await?;
        assert_eq!(claim.reserved_kind(), Some(EventKind::ResponseEnd));
        claim.publish()?;
        assert_eq!(runtime.progress().matched, 2);
        assert_eq!(runtime.progress().total, None);
        assert!(!claim.complete());
        runtime.commit_driver(3)?;
        assert!(!runtime.complete());
        let frontier = runtime
            .wait_for_frontier(99)
            .expect("empty schedule may still advance");
        let mut receipt = event(99, 1, EventKind::ResponseEnd);
        receipt.receipt_start = Some(2);
        runtime.push_stream(vec![receipt], true)?;
        frontier.changed().await;
        assert_eq!(runtime.progress().matched, 4);
        assert_eq!(runtime.progress().total, Some(4));
        assert!(runtime.complete());
        assert!(claim.complete());
        assert!(!runtime.contains(1));
        Ok(())
    }

    #[tokio::test]
    async fn a_bad_appended_row_releases_the_valid_prefix_to_the_driver() -> Result<()> {
        let runtime = SequenceRuntime::streaming_session(Some(Duration::ZERO), []);
        let mut changed = runtime.subscribe();
        let ready = event(3, 0, EventKind::SessionReady);
        let invalid = event(4, 1, EventKind::ResponseEnd);
        assert!(runtime.push_stream(vec![ready, invalid], false).is_err());
        assert!(changed.has_changed()?);
        changed.borrow_and_update();
        assert_eq!(runtime.expected(), Some(ready.source));
        runtime.commit_driver(3)?;
        assert!(!runtime.complete());
        assert!(runtime.expected().is_none());
        Ok(())
    }
}
