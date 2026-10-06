//! Bounded SSE observation shared by primary recording and request execution.
//! The deadline limits evidence acquisition; it is not a server EOF.

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::{HeaderMap, body::Incoming, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, Instant, sleep_until};

pub(crate) const OBSERVATION_WINDOW_MS: u64 = 50;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SseObservationPolicy {
    pub(crate) window_ms: u64,
}

impl Default for SseObservationPolicy {
    fn default() -> Self {
        Self {
            window_ms: OBSERVATION_WINDOW_MS,
        }
    }
}

impl SseObservationPolicy {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(
            self.window_ms == OBSERVATION_WINDOW_MS,
            "unsupported SSE observation window {}; expected {OBSERVATION_WINDOW_MS} ms",
            self.window_ms
        );
        Ok(())
    }
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

pub(crate) fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// Starts after receipt of the response head. Dropping an unfinished Incoming
/// at the deadline cancels the upstream response; no synthetic EOF is recorded.
pub(crate) async fn observe(
    mut body: Incoming,
    policy: SseObservationPolicy,
    limit: usize,
) -> Result<(Bytes, SseObservation)> {
    policy.validate()?;
    let deadline = Instant::now() + Duration::from_millis(policy.window_ms);
    let mut collected = Vec::new();
    let end = loop {
        let frame = tokio::select! {
            biased;
            _ = sleep_until(deadline) => break SseStreamEnd::ObservationWindowElapsed,
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else {
            break SseStreamEnd::ServerEof;
        };
        let frame = frame.context("failed to read SSE response body")?;
        if let Ok(data) = frame.into_data() {
            ensure!(
                collected.len().saturating_add(data.len()) <= limit,
                "SSE response body exceeds configured limit of {limit} bytes"
            );
            collected.extend_from_slice(&data);
        }
    };
    Ok((
        Bytes::from(collected),
        SseObservation {
            window_ms: policy.window_ms,
            end,
        },
    ))
}
