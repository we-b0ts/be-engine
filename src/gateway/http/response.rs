//! Upstream response acquisition and its protocol-specific deadline.

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{HeaderMap, Request, StatusCode};
use tokio::time::{Instant, timeout_at};

use crate::ProxyClient;
use crate::http::sse::{self, SseObservation, SseObservationPolicy};

pub(super) struct AcquiredResponse {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Bytes,
    pub(super) sse_observation: Option<SseObservation>,
}

pub(super) async fn acquire(
    client: &ProxyClient,
    request: Request<Full<Bytes>>,
    request_timeout: Duration,
    sse_body_limit: Option<usize>,
) -> Result<AcquiredResponse> {
    let deadline = Instant::now() + request_timeout;
    let response = timeout_at(deadline, super::transport::send_upstream(client, request))
        .await?
        .context("gateway upstream request failed")?;
    let status = response.status();
    let headers = response.headers().clone();
    let (body, sse_observation) =
        if let Some(sse_body_limit) = sse_body_limit.filter(|_| sse::is_event_stream(&headers)) {
            let (body, observation) = sse::observe(
                response.into_body(),
                SseObservationPolicy::default(),
                sse_body_limit,
            )
            .await?;
            (body, Some(observation))
        } else {
            let body = timeout_at(deadline, response.into_body().collect())
                .await?
                .context("failed to read gateway upstream response body")?
                .to_bytes();
            (body, None)
        };
    Ok(AcquiredResponse {
        status,
        headers,
        body,
        sse_observation,
    })
}
