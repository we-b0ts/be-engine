//! Compress a proven passive stream prefix and preserve its recorded final observation window.
use super::*;
use crate::interaction::replay::heartbeat_tail::Passive;
use tokio::time::{Duration, Instant};

#[derive(Debug)]
pub(in crate::replay) struct Pace {
    pub(super) first: usize,
    last: usize,
    last_output: Duration,
    end: Duration,
    cap: Duration,
    inflight: Option<usize>,
    written: Option<(usize, Instant)>,
    tail_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub(super) struct DispatchPace {
    pub(super) inflight: Option<usize>,
    written: Option<(usize, Instant)>,
}

impl DispatchPace {
    pub(super) fn deadline(
        &self,
        entry: &Entry,
        entries: &[Entry],
        cap: Duration,
        now: Instant,
    ) -> Instant {
        self.written.map_or(now, |(prior, at)| {
            at + entry_offset(entry)
                .saturating_sub(entry_offset(&entries[prior]))
                .min(cap)
        })
    }
}

impl NativeClock {
    pub(in crate::replay) fn prepare_fast(
        &mut self,
        case: &str,
        proof: &Passive,
        cap_ms: u64,
        setup_finished_ms: u64,
    ) -> Option<()> {
        let pending = self.pending.get(case)?;
        let anchor = self.entries[*pending.front()?].anchor;
        let (last_output_ms, _) = proof.outputs.last()?;
        let last_output = Duration::from_millis(*last_output_ms);
        let end = Duration::from_millis(proof.end_ms);
        let mut last = None;
        for &index in pending {
            let entry = &self.entries[index];
            let offset = entry.offset.to_std().ok()?;
            if entry.anchor != anchor || offset >= end {
                return None;
            }
            if offset < last_output + Duration::from_millis(1) {
                last = Some(index);
            }
        }
        let last = last?;
        let first = first_observed_slot(pending, &self.entries, &proof.outputs)?;
        let setup_finished = Duration::from_millis(setup_finished_ms.max(proof.setup_finished_ms));
        if entry_offset(&self.entries[first]) <= setup_finished {
            return None;
        }
        self.live.get_mut(case)?.fast = Some(Pace {
            first,
            last,
            last_output,
            end,
            cap: Duration::from_millis(cap_ms),
            inflight: None,
            written: None,
            tail_at: None,
        });
        Some(())
    }

    pub(in crate::replay) fn fast_tail_ready(&mut self, case: &str, now: Instant) -> bool {
        let Some(pace) = self.live.get_mut(case).and_then(|live| live.fast.as_mut()) else {
            return false;
        };
        let anchor = *pace.tail_at.get_or_insert(now);
        self.pending.get(case).is_some_and(VecDeque::is_empty)
            && pace.inflight.is_none()
            && now >= anchor + (pace.end - pace.last_output)
            && pace.written.is_some_and(|(index, at)| {
                index <= pace.last
                    || now >= at + pace.end.saturating_sub(entry_offset(&self.entries[index]))
            })
    }

    pub(in crate::replay) fn fast_written(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        slot: PushId,
        at: Instant,
    ) {
        let Some(live) = self.live.get_mut(case).filter(|live| live.epoch == epoch) else {
            return;
        };
        if let Some(pace) = &mut live.fast
            && let Some(index) = pace.inflight
            && self.entries[index].slot == slot
        {
            pace.inflight = None;
            pace.written = Some((index, at));
        }
        if let Some(index) = live.dispatch_pace.inflight
            && self.entries[index].slot == slot
        {
            live.dispatch_pace.inflight = None;
            live.dispatch_pace.written = Some((index, at));
        }
    }

    pub(super) fn fast_deadline(&self, case: &str) -> Option<Instant> {
        let pace = self.live.get(case)?.fast.as_ref()?;
        let index = *self.pending.get(case)?.front()?;
        pace.deadline(index, &self.entries)
    }
}

fn first_observed_slot(
    pending: &VecDeque<usize>,
    entries: &[Entry],
    outputs: &[(u64, [u8; 32])],
) -> Option<usize> {
    // Pair backwards so an identical earlier notification (including a
    // different room on the same subscription) cannot move the end of the
    // compressed prefix earlier than the last Source observation. Pairing
    // only sets a timing boundary: every native slot is still delivered.
    let mut candidates = pending.iter().rev().copied();
    let mut first = None;
    for &(observed_ms, fingerprint) in outputs.iter().rev() {
        let ceiling = Duration::from_millis(observed_ms) + Duration::from_millis(1);
        first = Some(candidates.find(|&index| {
            let entry = &entries[index];
            entry.fingerprint == fingerprint && entry_offset(entry) < ceiling
        })?);
    }
    first
}

impl Pace {
    pub(super) fn queued(&mut self, index: usize) {
        debug_assert!(self.inflight.is_none());
        self.inflight = Some(index);
    }

    pub(super) fn ready(
        &self,
        index: usize,
        entries: &[Entry],
        recorded_due: impl FnOnce() -> bool,
    ) -> bool {
        self.inflight.is_none()
            && if index < self.first {
                recorded_due()
            } else {
                self.deadline(index, entries)
                    .is_some_and(|due| Instant::now() >= due)
            }
    }

    fn deadline(&self, index: usize, entries: &[Entry]) -> Option<Instant> {
        if self.inflight.is_some() || index < self.first {
            return None;
        }
        if index > self.last {
            let offset = entry_offset(&entries[index]);
            let due = self.tail_at? + offset.saturating_sub(self.last_output);
            return Some(match self.written {
                Some((prior, at)) if prior > self.last => {
                    due.max(at + offset.saturating_sub(entry_offset(&entries[prior])))
                }
                _ => due,
            });
        }
        if index == self.first {
            return Some(Instant::now());
        }
        let (prior, at) = self.written?;
        let gap = entry_offset(&entries[index]).saturating_sub(entry_offset(&entries[prior]));
        Some(at + gap.min(self.cap))
    }
}

fn entry_offset(entry: &Entry) -> Duration {
    entry.offset.to_std().expect("validated native push offset")
}
