//! Physical lane predecessors are independent of command candidate buckets.
use std::collections::HashMap;
use uuid::Uuid;

use crate::ReplaySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneOwner {
    Case,
    Startup,
    Process,
    Unattributed,
}

impl LaneOwner {
    pub fn new(source: ReplaySource) -> Self {
        match source {
            ReplaySource::Case => Self::Case,
            ReplaySource::Startup => Self::Startup,
            ReplaySource::Process => Self::Process,
            ReplaySource::Unattributed => Self::Unattributed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaneKey {
    pub owner: LaneOwner,
    pub case: Option<String>,
    pub connection: Uuid,
}

#[derive(Debug, Default)]
pub struct LaneIndex {
    lanes: HashMap<LaneKey, Vec<(usize, Option<u64>)>>,
    references: HashMap<usize, (LaneKey, Option<u64>)>,
}

impl LaneIndex {
    pub fn register(&mut self, key: LaneKey, sequence: u64, index: usize) {
        self.register_optional(key, Some(sequence), index);
    }

    pub fn register_optional(&mut self, key: LaneKey, sequence: Option<u64>, index: usize) {
        self.lanes
            .entry(key.clone())
            .or_default()
            .push((index, sequence));
        self.references.insert(index, (key, sequence));
    }

    pub(crate) fn discard(&mut self, index: usize) -> bool {
        let Some((key, _)) = self.references.remove(&index) else {
            return false;
        };
        let entries = self.lanes.get_mut(&key).expect("registered lane");
        entries.retain(|&(existing, _)| existing != index);
        if entries.is_empty() {
            self.lanes.remove(&key);
            return true;
        }
        false
    }

    pub fn blocker(
        &self,
        candidate: usize,
        mut prevents_progress: impl FnMut(usize) -> bool,
    ) -> Option<usize> {
        let (key, sequence) = self.references.get(&candidate)?;
        self.lanes.get(key)?.iter().find_map(|(index, prior)| {
            (*prior < *sequence && prevents_progress(*index)).then_some(*index)
        })
    }

    /// Build a blocker-existence lookup for one selection with stable status.
    /// Only the lowest blocking sequence matters when no blocker identity is
    /// needed. Keep this cache local to the selection because status is live.
    pub fn blocked_candidates(
        &self,
        mut prevents_progress: impl FnMut(usize) -> bool,
    ) -> impl FnMut(usize) -> bool {
        let mut first_blocking = HashMap::new();
        move |candidate| {
            let Some((key, sequence)) = self.references.get(&candidate) else {
                return false;
            };
            first_blocking
                .entry(key)
                .or_insert_with(|| {
                    self.lanes
                        .get(key)
                        .into_iter()
                        .flatten()
                        .filter(|(index, _)| prevents_progress(*index))
                        .map(|(_, sequence)| *sequence)
                        .min()
                })
                .is_some_and(|first| first < *sequence)
        }
    }

    pub fn unique_slot(&self, key: &LaneKey, sequence: u64) -> Option<usize> {
        let mut slots = self
            .lanes
            .get(key)?
            .iter()
            .filter(|(_, prior)| *prior == Some(sequence));
        let (index, _) = slots.next()?;
        slots.next().is_none().then_some(*index)
    }

    pub fn previous_slot(&self, index: usize) -> Option<usize> {
        let (key, Some(sequence)) = self.references.get(&index)? else {
            return None;
        };
        let previous = self
            .lanes
            .get(key)?
            .iter()
            .filter_map(|(_, prior)| prior.filter(|prior| prior < sequence))
            .max()?;
        self.unique_slot(key, previous)
    }

    /// Effective lane members from `first` up to, but excluding, `candidate`.
    pub fn bounded_prefix(
        &self,
        first: usize,
        candidate: usize,
        limit: usize,
    ) -> Option<Vec<usize>> {
        let (first_key, Some(first_sequence)) = self.references.get(&first)? else {
            return None;
        };
        let (key, Some(sequence)) = self.references.get(&candidate)? else {
            return None;
        };
        if first_key != key || first_sequence >= sequence {
            return None;
        }
        let mut slots = Vec::new();
        for &(index, prior) in self.lanes.get(key)? {
            if let Some(prior) = prior.filter(|prior| (*first_sequence..*sequence).contains(prior))
            {
                if slots.len() == limit {
                    return None;
                }
                slots.push((prior, index));
            }
        }
        slots.sort_unstable();
        if slots.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }
        Some(slots.into_iter().map(|(_, index)| index).collect())
    }
}
