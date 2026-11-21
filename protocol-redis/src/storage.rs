//! Read-only Redis storage facts supplied by an execution or evidence host.
use crate::{recorded::RecordedExchange, session_binding::SessionExchange};
use anyhow::Result;
use traffic_model::attribution::DependencyScope;
use traffic_protocol::{connection::Endpoint, observation::normalize_host};

mod read_commutation;
pub use read_commutation::{ReadCommutationProof, prove_read_commutation};

pub trait StorageExchange: SessionExchange {
    fn native_record(&self) -> &RecordedExchange;
    fn arguments(&self) -> &[Vec<u8>];
    fn response_bytes(&self) -> Result<Vec<u8>>;
    fn explicitly_shared(&self) -> bool;
}

pub fn target_matches(target: &Endpoint, host: &str, port: u16) -> bool {
    target.host == normalize_host(host) && target.port == port
}
pub fn normalized_username(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}
pub fn is_other_ordinary_case(
    owner: &str,
    source: DependencyScope,
    case: Option<&str>,
    record: &RecordedExchange,
) -> bool {
    source == DependencyScope::Case
        && case.is_some_and(|case| case != owner)
        && record.cache_snapshot_rule.is_none()
        && !record.cache_snapshot_hit
        && record.run_owner_kind().is_none()
        && !record.session_setup
}
pub fn is_other_ordinary_exchange(owner: &str, exchange: &impl StorageExchange) -> bool {
    !exchange.explicitly_shared()
        && is_other_ordinary_case(
            owner,
            exchange.source(),
            exchange.case_id(),
            exchange.native_record(),
        )
}

pub mod observations;

pub mod activity;
pub mod append;

pub mod snapshot;

#[cfg(test)]
mod tests;
