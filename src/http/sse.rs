//! SSE content negotiation and decoding of retired observation metadata.

use hyper::{HeaderMap, header::ACCEPT};
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

/// Conservative recording selection, not Accept quality-value negotiation.
/// Even mixed JSON/SSE offers and `q=0` declare SSE for this policy.
pub(crate) fn accepts_event_stream(headers: &HeaderMap) -> bool {
    headers.get_all(ACCEPT).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|range| {
                range
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
            })
        })
    })
}
