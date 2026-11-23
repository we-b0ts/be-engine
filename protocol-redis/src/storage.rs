//! Read-only Redis storage facts supplied by an execution or evidence host.
use crate::{recorded::RecordedExchange, session_binding::SessionExchange};
use anyhow::Result;

pub trait StorageExchange: SessionExchange {
    fn native_record(&self) -> &RecordedExchange;
    fn arguments(&self) -> &[Vec<u8>];
    fn response_bytes(&self) -> Result<Vec<u8>>;
    fn explicitly_shared(&self) -> bool;
}

pub fn normalized_username(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}
pub mod snapshot;
