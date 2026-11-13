//! Decoding of retired SSE observation metadata.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SseObservationPolicy {
    pub window_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SseStreamEnd {
    ServerEof,
    ObservationWindowElapsed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SseObservation {
    pub window_ms: u64,
    pub end: SseStreamEnd,
}
