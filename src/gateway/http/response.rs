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

pub(super) struct AcquiredResponse {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Bytes,
    pub(super) stream: Option<Incoming>,
}

/// An offer is only an admission/encoding hint, never a response declaration.
pub(super) fn offers_stream(headers: &HeaderMap) -> bool {
    headers.get_all(hyper::header::ACCEPT).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|range| {
                matches!(
                    range
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                        .as_str(),
                    "text/event-stream" | "application/x-ndjson" | "application/ndjson"
                )
            })
        })
    })
}

/// Preserve uncompressed framing without selecting the response protocol.
pub(super) fn prefer_uncompressed_stream(request: &mut Request<Full<Bytes>>) {
    if offers_stream(request.headers()) {
        request.headers_mut().insert(
            hyper::header::ACCEPT_ENCODING,
            hyper::header::HeaderValue::from_static("identity"),
        );
    }
}

pub(super) async fn acquire(
    client: &ProxyClient,
    request: Request<Full<Bytes>>,
    request_timeout: Duration,
    raw_streaming: bool,
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
    if super::interaction::response_protocol(&headers).is_some_and(|protocol| {
        protocol != crate::interaction::model::Protocol::RawStream || raw_streaming
    }) {
        return Ok(AcquiredResponse {
            status,
            headers,
            body: Bytes::new(),
            stream: Some(response.into_body()),
        });
    }
    let body = {
        let mut response_body = response.into_body();
        match timeout_at(deadline, (&mut response_body).collect()).await {
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
        }
    };
    Ok(AcquiredResponse {
        status,
        headers,
        body,
        stream: None,
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
