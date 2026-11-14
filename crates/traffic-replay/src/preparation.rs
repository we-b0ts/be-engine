//! Immutable native membership and Source sequence facts supplied by providers.
use std::{collections::BTreeMap, sync::Arc};
use traffic_model::attribution::DependencyOwner;
use traffic_protocol::ProtocolId;

#[derive(Debug, Clone, Default)]
pub struct PreparedProtocol {
    pub members: Arc<[usize]>,
    pub sequence: Arc<[(usize, u64)]>,
}

pub type PreparedProtocols = BTreeMap<ProtocolId, PreparedProtocol>;

#[derive(Debug, Clone)]
pub struct RunSequenceReference {
    pub index: usize,
    pub sequence: u64,
    pub owner: DependencyOwner,
}
