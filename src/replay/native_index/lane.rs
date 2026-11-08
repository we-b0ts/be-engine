//! Physical lane predecessors are independent of command candidate buckets.
use std::collections::HashMap;
use uuid::Uuid;

use super::ReplaySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::replay) enum LaneOwner {
    Case,
    Startup,
    Process,
    Unattributed,
}

impl LaneOwner {
    pub(in crate::replay) fn new(source: ReplaySource) -> Self {
        match source {
            ReplaySource::Case => Self::Case,
            ReplaySource::Startup => Self::Startup,
            ReplaySource::Process => Self::Process,
            ReplaySource::Unattributed => Self::Unattributed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::replay) struct LaneKey {
    pub owner: LaneOwner,
    pub case: Option<String>,
    pub connection: Uuid,
}

#[derive(Debug, Default)]
pub(in crate::replay) struct LaneIndex {
    lanes: HashMap<LaneKey, Vec<(usize, Option<u64>)>>,
    references: HashMap<usize, (LaneKey, Option<u64>)>,
}

impl LaneIndex {
    pub(in crate::replay) fn register(&mut self, key: LaneKey, sequence: u64, index: usize) {
        self.register_optional(key, Some(sequence), index);
    }

    pub(in crate::replay) fn register_optional(
        &mut self,
        key: LaneKey,
        sequence: Option<u64>,
        index: usize,
    ) {
        self.lanes
            .entry(key.clone())
            .or_default()
            .push((index, sequence));
        self.references.insert(index, (key, sequence));
    }

    pub(in crate::replay) fn blocker(
        &self,
        candidate: usize,
        mut prevents_progress: impl FnMut(usize) -> bool,
    ) -> Option<usize> {
        let (key, sequence) = self.references.get(&candidate)?;
        self.lanes.get(key)?.iter().find_map(|(index, prior)| {
            (*prior < *sequence && prevents_progress(*index)).then_some(*index)
        })
    }

    pub(in crate::replay) fn unique_slot(&self, key: &LaneKey, sequence: u64) -> Option<usize> {
        let mut slots = self
            .lanes
            .get(key)?
            .iter()
            .filter(|(_, prior)| *prior == Some(sequence));
        let (index, _) = slots.next()?;
        slots.next().is_none().then_some(*index)
    }

    /// Effective lane members from `first` up to, but excluding, `candidate`.
    pub(in crate::replay) fn bounded_prefix(
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
