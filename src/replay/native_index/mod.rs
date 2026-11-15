//! Application lookup keys use the shared ordered candidate and lane indexes.

pub(crate) use traffic_replay::index::ScopePartition;
pub(crate) use traffic_replay::index::{LaneIndex, LaneKey, LaneOwner};

#[cfg(test)]
mod tests;

pub(crate) use traffic_replay::index::{CandidateCursor, CandidateIndex};
