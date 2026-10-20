//! Decoding of retired SSE observation metadata.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SseObservationPolicy {
    pub(crate) window_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SseStreamEnd {
    ServerEof,
    ObservationWindowElapsed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SseObservation {
    pub(crate) window_ms: u64,
    pub(crate) end: SseStreamEnd,
}
