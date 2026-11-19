//! One recording identity and observation-ordered dependency/event allocation.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

use anyhow::{Result, anyhow};
use traffic_model::recording::identity::IdentityKind;
use traffic_model::trace::RecordedEvent;
use traffic_recording_store::writer::RowStamp;
use uuid::Uuid;

#[derive(Clone)]
pub struct RecordingClock(Arc<Clock>);

struct Clock {
    recording_id: Uuid,
    started: Instant,
    sequences: Mutex<Sequences>,
    cases: AtomicU64,
    connections: AtomicU64,
}

#[derive(Default)]
struct Sequences {
    event: u64,
}

impl Default for RecordingClock {
    fn default() -> Self {
        Self(Arc::new(Clock {
            recording_id: Uuid::new_v4(),
            started: Instant::now(),
            sequences: Mutex::new(Sequences::default()),
            cases: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        }))
    }
}

impl RecordingClock {
    pub fn recording_id(&self) -> Uuid {
        self.0.recording_id
    }

    pub fn next_case_id(&self) -> Uuid {
        self.next_local(IdentityKind::Case, &self.0.cases)
    }

    pub fn next_connection_id(&self) -> Uuid {
        self.next_local(IdentityKind::Connection, &self.0.connections)
    }

    fn next_local(&self, kind: IdentityKind, counter: &AtomicU64) -> Uuid {
        let current = counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("recording-local identity exhausted");
        kind.bridge(self.recording_id(), current + 1)
    }

    /// Reserve an identity for an observation written only to the debug ledger.
    pub fn next_dependency(&self) -> Result<u64> {
        Ok(self.event(())?.sequence)
    }

    /// Reserve the request identity and its first event in one observation order.
    pub fn begin_dependency<Event>(
        &self,
        build: impl FnOnce(u64) -> Event,
    ) -> Result<(u64, RecordedEvent<Event>)> {
        self.publish(|batch| {
            let stamp = batch.next()?;
            Ok((stamp.sequence, recorded(&stamp, build(stamp.sequence))))
        })
    }

    /// Allocate order at observation time, before queuing asynchronous storage.
    pub fn event<Event>(&self, event: Event) -> Result<RecordedEvent<Event>> {
        self.publish(|batch| Ok(recorded(&batch.next()?, event)))
    }

    /// Keep allocation and FIFO submission in the same critical section. The
    /// caller reserves a queue slot before entering, so submission cannot wait.
    pub(crate) fn publish<T>(
        &self,
        submit: impl FnOnce(&mut SequenceBatch<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut sequences = self.0.sequences.lock().expect("recording clock poisoned");
        submit(&mut SequenceBatch {
            sequence: &mut sequences.event,
            offset_micros: self.0.started.elapsed().as_micros().try_into()?,
        })
    }
}

pub(crate) struct SequenceBatch<'a> {
    sequence: &'a mut u64,
    offset_micros: u64,
}

impl SequenceBatch<'_> {
    pub(crate) fn next(&mut self) -> Result<RowStamp> {
        *self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("recording event sequence exhausted"))?;
        Ok(RowStamp {
            sequence: *self.sequence,
            offset_micros: self.offset_micros,
        })
    }
}

pub(crate) fn recorded<Event>(stamp: &RowStamp, event: Event) -> RecordedEvent<Event> {
    RecordedEvent {
        sequence: stamp.sequence,
        offset_micros: stamp.offset_micros,
        event,
    }
}

#[cfg(test)]
mod tests;
