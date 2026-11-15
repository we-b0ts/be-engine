//! Protocol-projected output clocks share one independently observed primary close.
use crate::replay::ProtocolExchange;
use chrono::{DateTime, Utc};

pub(crate) struct SourceInput {
    pub epoch: DateTime<Utc>,
    pub close_ms: u64,
}

#[derive(Debug)]
pub(crate) struct SourceStream {
    pub reference: ProtocolExchange,
    pub started_at: DateTime<Utc>,
    pub headers_ms: u64,
    pub chunks_ms: Vec<u64>,
    pub end_ms: u64,
}
