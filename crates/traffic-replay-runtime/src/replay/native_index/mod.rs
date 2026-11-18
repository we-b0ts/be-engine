//! Application lookup keys use the shared ordered candidate and lane indexes.

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use traffic_replay::index::{
    CandidateIndex, LaneIndex, LaneKey, LaneOwner, ScopePartition,
};
