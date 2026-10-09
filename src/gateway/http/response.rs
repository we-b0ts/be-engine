//! Upstream response acquisition and its protocol-specific deadline.

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::{HeaderMap, Request, StatusCode};
use tokio::time::{Instant, timeout_at};

use super::recovery::TimeoutRecovery;
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
    mut recovery: Option<&mut TimeoutRecovery>,
) -> Result<AcquiredResponse> {
    let deadline = Instant::now() + request_timeout;
    let upstream = super::transport::send_upstream(client, request);
    tokio::pin!(upstream);
    let response = match timeout_at(deadline, &mut upstream).await {
        Ok(response) => response.context("gateway upstream request failed")?,
        Err(elapsed) => {
            if let Some(recovery) = recovery.as_mut() {
                recovery.begin().await;
                let result = async {
                    let response = upstream
                        .await
                        .context("gateway upstream request failed during recovery")?;
                    // Keep the transport alive through the entire response. Early SSE
                    // observation termination cannot establish Source completion here.
                    drain_body(&mut response.into_body()).await
                }
                .await;
                recovery.source_finished(&result).await;
            }
            return Err(elapsed.into());
        }
    };
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
            let mut response_body = response.into_body();
            let body = match timeout_at(deadline, (&mut response_body).collect()).await {
                Ok(body) => body
                    .context("failed to read gateway upstream response body")?
                    .to_bytes(),
                Err(elapsed) => {
                    if let Some(recovery) = recovery.as_mut() {
                        recovery.begin().await;
                        let result = drain_body(&mut response_body).await;
                        recovery.source_finished(&result).await;
                    }
                    return Err(elapsed.into());
                }
            };
            (body, None)
        };
    Ok(AcquiredResponse {
        status,
        headers,
        body,
        sse_observation,
    })
}

async fn drain_body(body: &mut Incoming) -> Result<()> {
    // The response is already a timeout. Observe completion without retaining
    // late response bytes, including potentially unbounded event streams.
    while let Some(frame) = body.frame().await {
        frame.context("failed to read recovered upstream response body")?;
    }
    Ok(())
}
