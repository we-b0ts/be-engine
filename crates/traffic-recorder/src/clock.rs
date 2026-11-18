//! One recording identity and observation-ordered dependency/event allocation.
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Result, anyhow};
use traffic_model::trace::RecordedEvent;
use uuid::Uuid;

#[derive(Clone)]
pub struct RecordingClock(Arc<Clock>);

struct Clock {
    recording_id: Uuid,
    started: Instant,
    sequences: Mutex<Sequences>,
}

#[derive(Default)]
struct Sequences {
    dependency: u64,
    event: u64,
}

impl Default for RecordingClock {
    fn default() -> Self {
        Self(Arc::new(Clock {
            recording_id: Uuid::new_v4(),
            started: Instant::now(),
            sequences: Mutex::new(Sequences::default()),
        }))
    }
}

impl RecordingClock {
    pub fn recording_id(&self) -> Uuid {
        self.0.recording_id
    }

    /// Every owner uses the same allocator, including calls still lacking an owner.
    pub fn next_dependency(&self) -> Result<u64> {
        let mut sequences = self.0.sequences.lock().expect("recording clock poisoned");
        sequences.dependency = sequences
            .dependency
            .checked_add(1)
            .ok_or_else(|| anyhow!("recording dependency sequence exhausted"))?;
        Ok(sequences.dependency)
    }

    /// Reserve the request identity and its first event in one observation order.
    pub fn begin_dependency<Event>(
        &self,
        build: impl FnOnce(u64) -> Event,
    ) -> Result<(u64, RecordedEvent<Event>)> {
        let mut sequences = self.0.sequences.lock().expect("recording clock poisoned");
        let dependency = sequences
            .dependency
            .checked_add(1)
            .ok_or_else(|| anyhow!("recording dependency sequence exhausted"))?;
        let sequence = sequences
            .event
            .checked_add(1)
            .ok_or_else(|| anyhow!("recording event sequence exhausted"))?;
        let offset_micros = self.0.started.elapsed().as_micros().try_into()?;
        sequences.dependency = dependency;
        sequences.event = sequence;
        Ok((
            dependency,
            RecordedEvent {
                sequence,
                offset_micros,
                event: build(dependency),
            },
        ))
    }

    /// Allocate order at observation time, before queuing asynchronous storage.
    pub fn event<Event>(&self, event: Event) -> Result<RecordedEvent<Event>> {
        let mut sequences = self.0.sequences.lock().expect("recording clock poisoned");
        sequences.event = sequences
            .event
            .checked_add(1)
            .ok_or_else(|| anyhow!("recording event sequence exhausted"))?;
        let offset_micros = self.0.started.elapsed().as_micros().try_into()?;
        Ok(RecordedEvent {
            sequence: sequences.event,
            offset_micros,
            event,
        })
    }
}

#[cfg(test)]
mod tests;
