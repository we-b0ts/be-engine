use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{HeaderMap, Method, Response, StatusCode, Uri};
use tracing::info;

use super::model::{ComparisonRecordingBody, ComparisonRecordingResponse};
use super::runtime::ComparisonRecordingRuntime;
use crate::config::HttpGatewayReadyConfig;
use crate::gateway::http::transport::{
    GatewayBody, build_downstream_response, build_upstream_request, build_upstream_uri,
    send_upstream, simple_response,
};
use crate::recorder::{CaseBodyCapture, capture_case_body, redact_headers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamErrorKind {
    Request,
    Timeout,
    ResponseTooLarge,
    ResponseDecode,
}

#[derive(Clone)]
pub(super) struct UpstreamCapture {
    pub(super) record: ComparisonRecordingResponse,
    pub(super) downstream: Option<(StatusCode, HeaderMap, Bytes)>,
    pub(super) error_kind: Option<UpstreamErrorKind>,
}

pub(super) enum LimitedBodyError {
    TooLarge,
    Read(anyhow::Error),
}

enum FetchOutcome {
    Complete {
        status: StatusCode,
        headers: HeaderMap,
        downstream: Option<Bytes>,
        captured: Bytes,
        original_len: usize,
        truncated: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ResponseDisposition {
    Downstream,
    CaptureOnly,
}

pub(super) async fn fetch_upstream(
    runtime: &ComparisonRecordingRuntime,
    upstream: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    disposition: ResponseDisposition,
) -> UpstreamCapture {
    let timestamp = Utc::now();
    let started = Instant::now();
    let operation = async {
        let outbound_uri = build_upstream_uri(upstream, uri)?;
        let outbound = build_upstream_request(
            method,
            outbound_uri,
            body,
            headers,
            runtime.gateway.preserve_host,
        )?;
        let response = send_upstream(&runtime.client, outbound)
            .await
            .map_err(anyhow::Error::from)?;
        let status = response.status();
        let response_headers = response.headers().clone();
        let body = collect_response(
            response.into_body(),
            runtime.comparison_recording.max_response_bytes,
            matches!(disposition, ResponseDisposition::Downstream),
        )
        .await?;
        Ok::<FetchOutcome, anyhow::Error>(FetchOutcome::Complete {
            status,
            headers: response_headers,
            downstream: body.downstream,
            captured: body.captured,
            original_len: body.original_len,
            truncated: body.truncated,
        })
    };
    match tokio::time::timeout(
        Duration::from_millis(runtime.comparison_recording.upstream_timeout_ms),
        operation,
    )
    .await
    {
        Ok(Ok(FetchOutcome::Complete {
            status,
            headers,
            downstream,
            captured,
            original_len,
            truncated,
        })) => {
            let body = response_body_capture(runtime, &headers, &captured, original_len, truncated);
            let record = response_record(
                runtime, timestamp, upstream, status, &headers, body, started,
            );
            let error_kind = record.body.as_ref().and_then(|body| {
                if body.truncated {
                    Some(UpstreamErrorKind::ResponseTooLarge)
                } else {
                    body.decode_error
                        .is_some()
                        .then_some(UpstreamErrorKind::ResponseDecode)
                }
            });
            UpstreamCapture {
                record,
                downstream: downstream.map(|body| (status, headers, body)),
                error_kind,
            }
        }
        Ok(Err(error)) => failed_capture(
            upstream,
            started.elapsed().as_millis(),
            error.to_string(),
            UpstreamErrorKind::Request,
        ),
        Err(_) => failed_capture(
            upstream,
            started.elapsed().as_millis(),
            "upstream request timed out".to_string(),
            UpstreamErrorKind::Timeout,
        ),
    }
}

struct CollectedResponse {
    downstream: Option<Bytes>,
    captured: Bytes,
    original_len: usize,
    truncated: bool,
}

async fn collect_response(
    mut body: Incoming,
    limit: usize,
    retain_downstream: bool,
) -> Result<CollectedResponse> {
    let mut captured = BytesMut::new();
    let mut downstream = retain_downstream.then(BytesMut::new);
    let mut original_len = 0_usize;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        original_len = original_len.saturating_add(data.len());
        if let Some(full) = downstream.as_mut() {
            full.extend_from_slice(&data);
        } else if captured.len() < limit {
            let remaining = limit - captured.len();
            captured.extend_from_slice(&data[..data.len().min(remaining)]);
        }
    }
    let downstream = downstream.map(BytesMut::freeze);
    let captured = downstream.as_ref().map_or_else(
        || captured.freeze(),
        |full| full.slice(..full.len().min(limit)),
    );
    Ok(CollectedResponse {
        downstream,
        captured,
        original_len,
        truncated: original_len > limit,
    })
}

fn response_record(
    runtime: &ComparisonRecordingRuntime,
    timestamp: chrono::DateTime<Utc>,
    upstream: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: CapturedResponseBody,
    started: Instant,
) -> ComparisonRecordingResponse {
    ComparisonRecordingResponse {
        version: 1,
        timestamp,
        upstream: upstream.to_string(),
        status: Some(status.as_u16()),
        headers: Some(redact_headers(
            headers,
            &runtime.config.recording.redact_headers,
        )),
        body: Some(body.body),
        duration_ms: started.elapsed().as_millis(),
        error: body.error,
    }
}

struct CapturedResponseBody {
    body: CaseBodyCapture,
    error: Option<String>,
}

fn response_body_capture(
    runtime: &ComparisonRecordingRuntime,
    headers: &HeaderMap,
    bytes: &[u8],
    original_len: usize,
    wire_truncated: bool,
) -> CapturedResponseBody {
    let mut body = capture_case_body(
        bytes,
        runtime.comparison_recording.max_response_bytes,
        runtime.config.recording.decoded_body_limit(),
        Some(headers),
    );
    body.original_len = original_len;
    body.truncated |= wire_truncated;
    let error = if wire_truncated {
        Some("response body exceeded comparison_recording.max_response_bytes".to_string())
    } else if body.truncated {
        Some(format!(
            "decoded response body exceeded configured decoded body limit of {} bytes",
            body.limit_bytes
        ))
    } else {
        body.decode_error
            .as_ref()
            .map(|error| format!("response body content decoding failed: {error}"))
    };
    CapturedResponseBody { body, error }
}

pub(super) fn failed_capture(
    upstream: &str,
    duration_ms: u128,
    error: String,
    kind: UpstreamErrorKind,
) -> UpstreamCapture {
    UpstreamCapture {
        record: ComparisonRecordingResponse {
            version: 1,
            timestamp: Utc::now(),
            upstream: upstream.to_string(),
            status: None,
            headers: None,
            body: None,
            duration_ms,
            error: Some(error),
        },
        downstream: None,
        error_kind: Some(kind),
    }
}

pub(super) fn downstream_response(capture: &UpstreamCapture) -> Response<GatewayBody> {
    capture.downstream.as_ref().map_or_else(
        || {
            simple_response(
                StatusCode::BAD_GATEWAY,
                capture.record.error.as_deref().unwrap_or("baseline failed"),
            )
        },
        |(status, headers, body)| build_downstream_response(*status, headers, body.clone()),
    )
}

pub(super) async fn collect_limited(
    mut body: Incoming,
    limit: usize,
) -> std::result::Result<Bytes, LimitedBodyError> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| LimitedBodyError::Read(error.into()))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if collected.len().saturating_add(data.len()) > limit {
            let remaining = limit.saturating_sub(collected.len());
            collected.extend_from_slice(&data[..remaining]);
            return Err(LimitedBodyError::TooLarge);
        }
        collected.extend_from_slice(&data);
    }
    Ok(collected.freeze())
}

pub(super) fn request_body_capture(
    bytes: &[u8],
    truncated: bool,
    original_len: Option<usize>,
) -> ComparisonRecordingBody {
    ComparisonRecordingBody {
        encoding: "base64",
        original_len,
        stored_len: bytes.len(),
        truncated,
        data: STANDARD.encode(bytes),
    }
}

pub(super) async fn run_ready_probe(runtime: ComparisonRecordingRuntime) {
    let ready = runtime.gateway.ready.clone();
    let mut interval = tokio::time::interval(Duration::from_millis(ready.interval_ms.max(1)));
    loop {
        interval.tick().await;
        let baseline = probe_once(&runtime, &runtime.baseline_upstream, &ready);
        let candidate = probe_once(
            &runtime,
            &runtime.comparison_recording.candidate_upstream,
            &ready,
        );
        if matches!(tokio::join!(baseline, candidate), (Ok(true), Ok(true))) {
            runtime.ready.store(true, Ordering::Release);
            runtime.store.summary().set_ready().await;
            runtime.ready_notify.notify_waiters();
            info!("baseline and candidate ready probes succeeded");
            return;
        }
    }
}

async fn probe_once(
    runtime: &ComparisonRecordingRuntime,
    upstream: &str,
    ready: &HttpGatewayReadyConfig,
) -> Result<bool> {
    let path = if ready.path.starts_with('/') {
        ready.path.clone()
    } else {
        format!("/{}", ready.path)
    };
    let uri = path.parse::<Uri>()?;
    let capture = fetch_upstream(
        runtime,
        upstream,
        &Method::GET,
        &uri,
        &HeaderMap::new(),
        Bytes::new(),
        ResponseDisposition::CaptureOnly,
    )
    .await;
    Ok(capture.record.status == Some(ready.success_status))
}
