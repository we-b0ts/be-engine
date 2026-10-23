//! Ordinary HTTP delivery, bounded capture and case-owned asynchronous publication.
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body::Body;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Response, StatusCode, Uri, body::Incoming};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use tracing::warn;
use uuid::Uuid;

use super::{
    recovery::TimeoutRecovery,
    response,
    transport::{GatewayBody, build_downstream_response, simple_response},
    with_gateway_headers,
};
use crate::http::{
    forward::{HostHeaderPolicy, append_end_to_end_headers},
    rewrite::{self, RewriteInput},
};
use crate::recorder::http::case::{
    CaseRequestRecord, CaseResponseRecord, finalize_owned_http_case,
};
use crate::recorder::{
    CaseContext, HeaderMapSnapshot, HttpExchangeEvent, RecorderEvent, capture_body,
    capture_body_with_original_len, capture_case_body, redact_headers,
};
use crate::{ActiveCaseGuard, AppState, DiscoveredTcpTarget};

mod body;
#[cfg(test)]
mod tests;

pub(super) struct CaptureContext {
    pub state: AppState,
    pub id: Uuid,
    pub client_addr: Option<String>,
    pub method: Method,
    pub original_uri: Uri,
    pub authority: Option<String>,
    pub request_headers: HeaderMapSnapshot,
    pub request_body: Bytes,
    pub started: Instant,
    pub request_started_at: DateTime<Utc>,
    pub matched_rule: Option<String>,
    pub case: Option<CaseContext>,
    pub request_record: Option<CaseRequestRecord>,
    pub upstream: String,
    pub guard: Option<Arc<ActiveCaseGuard>>,
}

pub(super) async fn forward(
    context: CaptureContext,
    status: StatusCode,
    headers: HeaderMap,
    mut upstream: Incoming,
    deadline: tokio::time::Instant,
    mut recovery: Option<TimeoutRecovery>,
) -> Response<GatewayBody> {
    let input = RewriteInput {
        method: &context.method,
        uri: &context.original_uri,
        authority: context.authority.as_deref(),
        status,
        headers: &headers,
        body: &[],
    };
    if context.state.config().http_response_rewrite.is_enabled()
        && context
            .state
            .config()
            .http_response_rewrite
            .rules
            .iter()
            .any(|rule| rewrite::matches(rule, &input))
    {
        return rewritten(context, status, headers, upstream, deadline, recovery).await;
    }
    let (sender, body, failed) = body::channel(
        context.state.clone(),
        context.case.as_ref().map(|case| case.id),
        context.started,
        upstream.size_hint().exact(),
    );
    let mut response = Response::new(body);
    *response.status_mut() = status;
    append_end_to_end_headers(&headers, response.headers_mut(), HostHeaderPolicy::Preserve);
    // Transfer-Encoding is regenerated for this hop; preserve declared trailers.
    if let Some(trailers) = headers.get(hyper::header::TRAILER) {
        response
            .headers_mut()
            .insert(hyper::header::TRAILER, trailers.clone());
    }
    mark_case(&context, &mut response);
    tokio::spawn(async move {
        let mut payload = CapturedPayload::new(&context.state);
        let mut error = None;
        let mut timed_out = false;
        loop {
            let frame = match tokio::time::timeout_at(deadline, upstream.frame()).await {
                Ok(Some(Ok(frame))) => frame,
                Ok(None) => break,
                Ok(Some(Err(cause))) => {
                    failed.store(true, Ordering::Release);
                    error = Some(format!(
                        "failed to read gateway upstream response body: {cause}"
                    ));
                    let _ = sender.try_send(Err(anyhow::anyhow!(error.clone().unwrap())));
                    break;
                }
                Err(_) => {
                    failed.store(true, Ordering::Release);
                    error = Some("gateway upstream response body timed out".into());
                    let _ = sender.try_send(Err(anyhow::anyhow!(error.clone().unwrap())));
                    timed_out = true;
                    break;
                }
            };
            if let Some(data) = frame.data_ref() {
                payload.append(data);
            }
            if !sender.is_closed() {
                match tokio::time::timeout_at(deadline, sender.send(Ok(frame))).await {
                    Ok(_) => {}
                    Err(_) => {
                        failed.store(true, Ordering::Release);
                        error = Some("gateway downstream response delivery timed out".into());
                        timed_out = true;
                        break;
                    }
                }
            }
        }
        // Body EOF is an external response boundary, not the tail/publication boundary.
        drop(sender);
        if timed_out && let Some(recovery) = &mut recovery {
            recovery
                .observe_source_completion(response::drain_body(&mut upstream))
                .await;
        }
        context
            .finish(status, headers, payload, Vec::new(), error, recovery)
            .await;
    });
    response
}

async fn rewritten(
    context: CaptureContext,
    status: StatusCode,
    mut headers: HeaderMap,
    mut upstream: Incoming,
    deadline: tokio::time::Instant,
    mut recovery: Option<TimeoutRecovery>,
) -> Response<GatewayBody> {
    let result = async {
        let mut bytes = response::collect_body(&mut upstream, deadline, recovery.as_mut()).await?;
        let targets = if let Some(rewritten) = rewrite::apply(
            &context.state.config().http_response_rewrite,
            context.state.dns_registry(),
            context.state.kubectl_proxy_manager(),
            context.state.ca().ca_cert_pem_ref(),
            context.state.config().recording.decoded_body_limit(),
            RewriteInput {
                method: &context.method,
                uri: &context.original_uri,
                authority: context.authority.as_deref(),
                status,
                headers: &headers,
                body: &bytes,
            },
        )
        .await?
        {
            headers = rewritten.headers;
            bytes = rewritten.body;
            rewritten.discovered_tcp_targets
        } else {
            Vec::new()
        };
        Ok::<_, anyhow::Error>((bytes, targets))
    }
    .await;
    match result {
        Ok((bytes, targets)) => {
            let mut response = build_downstream_response(status, &headers, bytes.clone());
            mark_case(&context, &mut response);
            let payload = CapturedPayload {
                received: bytes.len(),
                bytes: bytes[..bytes
                    .len()
                    .min(context.state.config().recording.max_body_bytes)]
                    .to_vec(),
                limit: context.state.config().recording.max_body_bytes,
            };
            tokio::spawn(context.finish(status, headers, payload, targets, None, recovery));
            response
        }
        Err(error) => {
            let timed_out = error.is::<tokio::time::error::Elapsed>();
            let message = format!("{error:#}");
            let payload = CapturedPayload::new(&context.state);
            let mut response = simple_response(
                if timed_out {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                },
                &message,
            );
            mark_case(&context, &mut response);
            tokio::spawn(context.finish(
                status,
                headers,
                payload,
                Vec::new(),
                Some(message),
                recovery,
            ));
            response
        }
    }
}

fn mark_case(context: &CaptureContext, response: &mut Response<GatewayBody>) {
    for header in [
        "x-traffic-e2e-case-id",
        "x-traffic-e2e-session-id",
        "x-traffic-e2e-finite-response",
    ] {
        response.headers_mut().remove(header);
    }
    if let Some(case) = &context.case {
        mark_admitted_case(case.id, response);
    }
}

pub(super) fn mark_admitted_case(case_id: Uuid, response: &mut Response<GatewayBody>) {
    response.headers_mut().insert(
        "x-traffic-e2e-finite-response",
        hyper::header::HeaderValue::from_static("1"),
    );
    response.headers_mut().insert(
        "x-traffic-e2e-case-id",
        case_id.to_string().parse().expect("UUID header"),
    );
}

struct CapturedPayload {
    bytes: Vec<u8>,
    received: usize,
    limit: usize,
}
impl CapturedPayload {
    fn new(state: &AppState) -> Self {
        Self {
            bytes: Vec::new(),
            received: 0,
            limit: state.config().recording.max_body_bytes,
        }
    }
    fn append(&mut self, bytes: &[u8]) {
        self.received = self.received.saturating_add(bytes.len());
        let stored = bytes.len().min(self.limit.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..stored]);
    }
}

impl CaptureContext {
    async fn finish(
        self,
        status: StatusCode,
        headers: HeaderMap,
        payload: CapturedPayload,
        targets: Vec<DiscoveredTcpTarget>,
        error: Option<String>,
        recovery: Option<TimeoutRecovery>,
    ) {
        let Some(case) = &self.case else {
            return;
        };
        let _guard = self
            .guard
            .as_ref()
            .expect("matched response retains case admission");
        let timestamp = Utc::now();
        let duration_ms = self.started.elapsed().as_millis();
        let recording = &self.state.config().recording;
        let captured_headers = redact_headers(&headers, &recording.redact_headers);
        let event = HttpExchangeEvent {
            outcome: crate::DependencyExchangeOutcome::Response,
            id: self.id,
            timestamp,
            request_started_at: self.request_started_at,
            client_addr: self.client_addr,
            scheme: "http_gateway".into(),
            method: self.method.to_string(),
            uri: self.original_uri.to_string(),
            authority: self.authority,
            request_headers: with_gateway_headers(
                self.request_headers,
                self.matched_rule.as_deref(),
                &self.upstream,
            ),
            request_body: capture_body(&self.request_body, recording.max_body_bytes),
            response_status: Some(status.as_u16()),
            response_headers: Some(captured_headers.clone()),
            response_body: Some(capture_body_with_original_len(
                &payload.bytes,
                payload.received,
            )),
            response_stream: None,
            discovered_tcp_targets: targets,
            duration_ms,
            error: error.clone(),
        };
        if let Err(error) = self
            .state
            .recorder()
            .record(RecorderEvent::HttpExchange(event))
            .await
        {
            warn!(%error, case_id = %case.id, "failed to record HTTP gateway exchange");
        }
        let mut body = capture_case_body(
            &payload.bytes,
            recording.max_body_bytes,
            recording.decoded_body_limit(),
            Some(&headers),
        );
        body.original_len = payload.received;
        body.truncated |= payload.received > payload.bytes.len();
        let response = CaseResponseRecord {
            timestamp,
            matched_rule: self.matched_rule,
            upstream: self.upstream,
            status: Some(status.as_u16()),
            headers: Some(captured_headers),
            body: Some(body),
            duration_ms,
            error,
            sse_observation: None,
            interaction: None,
        };
        let drain = self.state.drain_active_case_dependencies(case.id).await;
        if let Some(recovery) = recovery {
            recovery.dependencies_drained(drain.as_ref()).await;
        }
        let publication = self
            .state
            .inner
            .active_cases
            .register_case_publication(case.id)
            .expect("case ownership retained through publication");
        if let Err(error) = finalize_owned_http_case(
            self.state.recorder(),
            &publication,
            case,
            self.request_record.expect("matched request evidence"),
            response,
            self.state.active_case_invalidation(case.id).or(drain),
        )
        .await
        {
            self.state.begin_case_quiescing();
            warn!(%error, case_id = %case.id, "failed to finalize ordinary HTTP gateway case");
        }
    }
}
