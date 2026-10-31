//! Physical lane predecessors are independent of command candidate buckets.
use std::collections::HashMap;
use uuid::Uuid;

use super::ReplaySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::replay) enum LaneOwner {
    Case,
    Startup,
    Process,
}

impl LaneOwner {
    pub(in crate::replay) fn new(source: ReplaySource) -> Self {
        match source {
            ReplaySource::Case => Self::Case,
            ReplaySource::Startup => Self::Startup,
            ReplaySource::Process => Self::Process,
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
}
