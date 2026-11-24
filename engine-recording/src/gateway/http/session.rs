//! Source-facing HTTP capture for the ordered recording session.
use std::time::Duration;

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use chrono::Utc;
use http_body::Body as _;
use http_body_util::{BodyExt as _, Limited, StreamBody};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri, body::Incoming};
use tokio::time::{Instant, timeout_at};
use traffic_model::session::SessionEvent;
use uuid::Uuid;

use super::rules::{RuleDecision, evaluate_request, request_authority};
use super::transport::{
    GatewayBody, build_fixed_response, build_upstream_request, build_upstream_uri, send_upstream,
    simple_response,
};
use crate::AppState;
use crate::config::HttpGatewayConfig;
use crate::http::forward::{HostHeaderPolicy, append_end_to_end_headers};
use crate::protocols::recording::events::{capture_case_body, redact_headers};
use crate::protocols::recording::http::case::{CaseRequestRecord, CaseResponseRecord};

pub(super) async fn handle(
    mut request: Request<Incoming>,
    state: &AppState,
    config: &HttpGatewayConfig,
    connection: Uuid,
    client_addr: Option<String>,
) -> Response<GatewayBody> {
    let upgrade = request
        .headers_mut()
        .remove(super::SESSION_UPGRADE_HEADER)
        .is_some()
        || request.headers().contains_key(hyper::header::UPGRADE)
        || request.method() == Method::CONNECT;
    match evaluate_request(
        &config.exclude_rules,
        &config.rules,
        request.method(),
        request.uri(),
        request.headers(),
    ) {
        RuleDecision::Matched(_) => {}
        _ => {
            return config.fixed_response.as_ref().map_or_else(
                || simple_response(StatusCode::NOT_FOUND, "recorder admission declined"),
                build_fixed_response,
            );
        }
    }
    if upgrade {
        state.fail_session_recording("unsupported HTTP upgrade in session recording");
        return simple_response(
            StatusCode::NOT_IMPLEMENTED,
            "HTTP upgrade not supported by session recording",
        );
    }
    let deadline = Instant::now() + Duration::from_millis(config.request_timeout_ms);
    let (parts, body) = request.into_parts();
    let Ok(Ok(collected)) = timeout_at(
        deadline,
        Limited::new(body, state.config().recording.max_body_bytes).collect(),
    )
    .await
    else {
        return simple_response(
            StatusCode::BAD_REQUEST,
            "request body could not be admitted",
        );
    };
    if collected.trailers().is_some() {
        state.fail_session_recording("unsupported HTTP request trailers in session recording");
        return simple_response(
            StatusCode::NOT_IMPLEMENTED,
            "HTTP request trailers not supported by session recording",
        );
    }
    let request = Request::from_parts(parts, collected.to_bytes());
    match forward(
        state,
        config,
        request,
        deadline,
        Origin::Ingress {
            connection,
            client_addr,
        },
    )
    .await
    {
        Ok(response) => response,
        Err(error) => error.response(),
    }
}

pub(super) async fn probe(
    state: &AppState,
    config: &HttpGatewayConfig,
    uri: Uri,
) -> Result<Response<GatewayBody>> {
    let request = Request::builder().uri(uri).body(Bytes::new())?;
    let deadline = Instant::now() + Duration::from_millis(config.request_timeout_ms);
    forward(state, config, request, deadline, Origin::Readiness)
        .await
        .map_err(|error| error.source)
}

enum Origin {
    Ingress {
        connection: Uuid,
        client_addr: Option<String>,
    },
    Readiness,
}

struct ForwardError {
    status: StatusCode,
    source: anyhow::Error,
}

impl ForwardError {
    fn capture(state: &AppState, source: anyhow::Error) -> Self {
        state.fail_session_recording(&source);
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            source,
        }
    }

    fn response(self) -> Response<GatewayBody> {
        simple_response(self.status, "session recording request failed")
    }
}

async fn forward(
    state: &AppState,
    config: &HttpGatewayConfig,
    request: Request<Bytes>,
    deadline: Instant,
    origin: Origin,
) -> std::result::Result<Response<GatewayBody>, ForwardError> {
    let (parts, body) = request.into_parts();
    let build = || {
        let uri = build_upstream_uri(&config.matched_upstream, &parts.uri)?;
        let preserve_host = config.preserve_host && matches!(&origin, Origin::Ingress { .. });
        let mut outbound = build_upstream_request(
            &parts.method,
            uri,
            body.clone(),
            &parts.headers,
            preserve_host,
        )?;
        super::response::prefer_uncompressed_stream(&mut outbound);
        Ok::<_, anyhow::Error>(outbound)
    };
    let outbound = build().map_err(|error| ForwardError::capture(state, error))?;
    let request = record_request(state, config, &parts, outbound.headers(), &body, origin)
        .map_err(|error| ForwardError::capture(state, error))?;
    let exchange = state.recorder().capture.next_case_id();
    state
        .session_event(SessionEvent::PrimaryRequest { exchange, request })
        .map_err(|error| ForwardError::capture(state, error))?;
    let mut observation = Exchange {
        state: state.clone(),
        exchange,
        next_part: 1,
        terminal: false,
    };
    let started = Instant::now();
    let upstream = match timeout_at(deadline, send_upstream(state.client(), outbound)).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let _ = observation.cancel("source_request_failed");
            return Err(ForwardError {
                status: StatusCode::BAD_GATEWAY,
                source: error.into(),
            });
        }
        Err(error) => {
            let _ = observation.cancel("source_response_timeout");
            return Err(ForwardError {
                status: StatusCode::GATEWAY_TIMEOUT,
                source: error.into(),
            });
        }
    };
    let (mut parts, body) = upstream.into_parts();
    let mut headers = HeaderMap::new();
    append_end_to_end_headers(&parts.headers, &mut headers, HostHeaderPolicy::Preserve);
    for trailer in parts.headers.get_all(hyper::header::TRAILER) {
        headers.append(hyper::header::TRAILER, trailer.clone());
    }
    parts.headers = headers;
    let response = serde_json::to_value(CaseResponseRecord {
        timestamp: Utc::now(),
        matched_rule: None,
        upstream: config.matched_upstream.clone(),
        status: Some(parts.status.as_u16()),
        headers: Some(observation.redacted(&parts.headers)),
        body: None,
        duration_ms: started.elapsed().as_millis(),
        error: None,
        sse_observation: None,
        interaction: None,
    })
    .map_err(|error| ForwardError::capture(state, error.into()))?;
    state
        .session_event(SessionEvent::PrimaryResponseHeaders { exchange, response })
        .map_err(|error| ForwardError::capture(state, error))?;
    let body = if body.is_end_stream() {
        observation
            .end()
            .map_err(|error| ForwardError::capture(state, error))?;
        body.map_err(anyhow::Error::from).boxed_unsync()
    } else {
        observe_body(body, observation, deadline)
    };
    Ok(Response::from_parts(parts, body))
}

fn record_request(
    state: &AppState,
    config: &HttpGatewayConfig,
    parts: &hyper::http::request::Parts,
    source_headers: &HeaderMap,
    body: &Bytes,
    origin: Origin,
) -> Result<serde_json::Value> {
    let (connection, client_addr, probe) = match origin {
        Origin::Ingress {
            connection,
            client_addr,
        } => (connection, client_addr, false),
        Origin::Readiness => (state.recorder().capture.next_connection_id(), None, true),
    };
    let mut stored = serde_json::to_value(CaseRequestRecord {
        timestamp: Utc::now(),
        client_addr,
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        api_pattern: None,
        authority: request_authority(&parts.uri, &parts.headers),
        matched_rule: None,
        upstream: config.matched_upstream.clone(),
        headers: state.recorder().capture_request_headers(source_headers)?,
        body: capture_case_body(body, body.len(), body.len(), None),
        sse_observation: None,
        interaction: None,
    })?;
    stored["session_connection"] = serde_json::to_value(connection)?;
    if probe {
        stored["_session_probe"] = true.into();
    }
    Ok(stored)
}

struct Exchange {
    state: AppState,
    exchange: Uuid,
    next_part: u64,
    terminal: bool,
}

impl Exchange {
    fn redacted(
        &self,
        headers: &HeaderMap,
    ) -> crate::protocols::recording::events::HeaderMapSnapshot {
        redact_headers(headers, &self.state.config().recording.redact_headers)
    }

    fn frame(&mut self, frame: &hyper::body::Frame<Bytes>) -> Result<()> {
        let exchange = self.exchange;
        if let Some(data) = frame.data_ref() {
            self.state
                .session_event(SessionEvent::PrimaryResponsePart {
                    exchange,
                    part: self.next_part,
                    data_base64: STANDARD.encode(data),
                })?;
            self.next_part += 1;
        } else if let Some(trailers) = frame.trailers_ref() {
            self.state
                .session_event(SessionEvent::PrimaryResponseTrailers {
                    exchange,
                    trailers: serde_json::to_value(self.redacted(trailers))?,
                })?;
        }
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        self.terminal = true;
        self.state.session_event(SessionEvent::PrimaryResponseEnd {
            exchange: self.exchange,
        })
    }

    fn cancel(&mut self, reason: &str) -> Result<()> {
        self.terminal = true;
        self.state.session_event(SessionEvent::PrimaryCancel {
            exchange: self.exchange,
            reason: reason.to_owned(),
        })
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if !self.terminal {
            let _ = self.cancel("client_cancelled");
        }
    }
}

fn observe_body(body: Incoming, observation: Exchange, deadline: Instant) -> GatewayBody {
    let frames =
        futures_util::stream::unfold(Some((body, observation)), move |running| async move {
            let (mut body, mut observation) = running?;
            match timeout_at(deadline, body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    let result = observation.frame(&frame).and_then(|()| {
                        if body.is_end_stream() {
                            observation.end()?;
                        }
                        Ok(frame)
                    });
                    let running =
                        (result.is_ok() && !observation.terminal).then_some((body, observation));
                    Some((result, running))
                }
                Ok(None) => observation.end().err().map(|error| (Err(error), None)),
                Ok(Some(Err(error))) => {
                    let error = observation
                        .cancel("source_response_reset")
                        .err()
                        .unwrap_or_else(|| error.into());
                    Some((Err(error), None))
                }
                Err(error) => {
                    let error = observation
                        .cancel("source_response_timeout")
                        .err()
                        .unwrap_or_else(|| anyhow!(error));
                    Some((Err(error.context("Source response body timed out")), None))
                }
            }
        });
    StreamBody::new(frames).boxed_unsync()
}
