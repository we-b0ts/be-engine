use std::convert::Infallible;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::AccessDecision;
use crate::config::{HttpGatewayConfig, HttpGatewayFallbackMode};
use crate::http::access::classify_method;
use crate::protocols::recording::events::{
    HeaderMapSnapshot, HttpExchangeEvent, ProxyErrorEvent, RecorderEvent, capture_case_body,
};
use crate::protocols::recording::http::case::{
    CaseRequestRecord, CaseResponseRecord, finalize_owned_http_case,
};
use crate::recorder::{CaseContext, PrimaryCaseDescriptor, capture_body};
use crate::recording_control::RecordingListener;

mod admission;
pub mod interaction;
mod lifecycle;
mod ordinary;
mod ready;
mod recovery;
mod response;
pub mod rules;
#[cfg(test)]
mod timeout_tests;
pub mod transport;

use admission::try_admit_case;
use rules::{RuleDecision, evaluate_request, request_authority, resolve_case_group};
use transport::{
    GatewayBody, build_fixed_response, build_upstream_request, build_upstream_uri, simple_response,
};

pub async fn run(state: AppState) -> Result<()> {
    let listen = state.config().http_gateway.listen;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind HTTP gateway {listen}"))?;
    run_with_listener(state, listener).await
}

// Keep ownership of ephemeral listeners through startup in concurrent tests.
pub async fn run_with_listener(state: AppState, listener: TcpListener) -> Result<()> {
    let config = state.config().http_gateway.clone();
    state.mark_recording_listener_ready(RecordingListener::HttpGateway);
    info!(
        listen = %config.listen,
        matched_upstream = %config.matched_upstream,
        fallback_upstream = %config.fallback_upstream,
        fallback_mode = ?config.fallback_mode,
        "HTTP gateway listening"
    );

    let mut ready_task = if config.ready.enabled {
        let ready_state = state.clone();
        let ready_config = config.clone();
        Some(tokio::spawn(async move {
            ready::run(ready_state, ready_config).await
        }))
    } else {
        None
    };

    loop {
        let accepted = tokio::select! {
            ready_result = async {
                ready_task
                    .as_mut()
                    .expect("ready task branch is guarded")
                    .await
            }, if ready_task.is_some() => {
                ready_task = None;
                ready_result
                    .context("HTTP gateway ready task failed")?
                    .context("HTTP gateway readiness failed")?;
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, peer_addr) = accepted.context("failed to accept HTTP gateway client")?;
        stream
            .set_nodelay(true)
            .context("failed to enable TCP_NODELAY for HTTP gateway client")?;
        let state = state.clone();
        let config = config.clone();
        let mut protocol_session =
            match crate::protocols::http_session(state.dependency_providers()) {
                Ok(session) => session,
                Err(error) => {
                    warn!(%error, "failed to create HTTP protocol session");
                    continue;
                }
            };
        tokio::spawn(async move {
            let termination =
                match crate::http::termination::ClientTermination::with_control(&stream) {
                    Ok(termination) => termination,
                    Err(error) => {
                        warn!(%error, "failed to observe HTTP gateway client");
                        return;
                    }
                };
            let io = TokioIo::new(stream);
            let client_addr = Some(peer_addr.to_string());
            let service = service_fn(move |req| {
                let state = state.clone();
                let config = config.clone();
                let client_addr = client_addr.clone();
                async move {
                    Ok::<_, Infallible>(
                        handle_gateway_request(req, state, config, client_addr).await,
                    )
                }
            });

            if let Err(err) = termination
                .serve(
                    protocol_session
                        .connection(io.into_inner(), service, true)
                        .with_upgrades(),
                )
                .await
            {
                warn!(error = %err, "HTTP gateway connection ended with error");
            }
        });
    }
}

async fn handle_gateway_request(
    req: Request<Incoming>,
    state: AppState,
    config: HttpGatewayConfig,
    client_addr: Option<String>,
) -> Response<GatewayBody> {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let request_started_at = Utc::now();
    let method = req.method().clone();
    let original_uri = req.uri().clone();
    let operation_class = classify_method(&method);
    if state.access_decision(operation_class) == AccessDecision::Reject {
        state
            .record_readonly_rejection(
                "http_gateway",
                operation_class,
                method.to_string(),
                client_addr,
                Some(original_uri.to_string()),
                "HTTP method is classified as a write operation",
            )
            .await;
        return simple_response(
            StatusCode::FORBIDDEN,
            "request blocked by recording access policy",
        );
    }
    let request_headers = req.headers().clone();
    if let Some(protocol) = interaction::request_protocol(&req) {
        return interaction::handle(req, state, config, client_addr, protocol).await;
    }
    let request_headers_for_record =
        match state.recorder().capture_request_headers(&request_headers) {
            Ok(headers) => headers,
            Err(error) => {
                warn!(error = %error, "failed to protect recorded HTTP request headers");
                return simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to protect recorded request headers",
                );
            }
        };
    let authority = request_authority(&original_uri, &request_headers);
    let recording_api_pattern = state
        .recording_api_pattern(&method, &original_uri)
        .map(str::to_string);
    let matched_rule = match evaluate_request(
        &config.exclude_rules,
        &config.rules,
        &method,
        &original_uri,
        &request_headers,
    ) {
        RuleDecision::Matched(_)
            if !config.record_streaming && response::offers_stream(&request_headers) =>
        {
            info!(
                method = %method,
                uri = %original_uri,
                "HTTP gateway request offers a stream; streaming recording disabled, using fallback"
            );
            None
        }
        RuleDecision::Matched(rule) if state.should_record_api(&method, &original_uri) => {
            Some(rule)
        }
        RuleDecision::Matched(_) => {
            info!(
                method = %method,
                uri = %original_uri,
                "HTTP gateway request is outside the runtime recording API selection"
            );
            None
        }
        RuleDecision::Excluded { name } => {
            info!(exclude_rule = %name, uri = %original_uri, "HTTP gateway request excluded from matching");
            None
        }
        RuleDecision::Unmatched => None,
    };
    let matched_rule_name = matched_rule.as_ref().map(|rule| rule.name.clone());
    let candidate_case = matched_rule.as_ref().map(|rule| {
        let group = recording_api_pattern.as_ref().map_or_else(
            || resolve_case_group(&original_uri, &config.case_path_patterns),
            |pattern| resolve_case_group(&original_uri, std::slice::from_ref(pattern)),
        );
        let max_cases = config.per_api_case_limits.limit_for(&group.pattern);
        let recording_api = recording_api_pattern
            .as_ref()
            .map(|pattern| format!("{method} {pattern}"));
        (
            CaseContext {
                id,
                rule_name: rule.name.clone(),
                uri_group: Some(group.directory),
            },
            group.pattern,
            recording_api,
            max_cases,
        )
    });
    let request_body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return record_gateway_error(GatewayErrorContext {
                state,
                id,
                client_addr,
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body: Bytes::new(),
                started,
                request_started_at,
                matched_rule: matched_rule_name,
                case: None,
                should_record: false,
                target: None,
                err: anyhow!("failed to read gateway request body: {err}"),
            })
            .await;
        }
    };
    let mut should_record = false;
    let mut case = None;
    let mut admitted_case_pattern = None;
    let mut upstream_base = config.fallback_upstream.clone();
    let mut case_guard = None;

    if let Some((candidate_case, case_pattern, recording_api, max_cases)) = candidate_case {
        let descriptor = PrimaryCaseDescriptor::http(method.as_str(), &case_pattern);
        if let Some(guard) = try_admit_case(
            &state,
            &candidate_case,
            &descriptor,
            recording_api.as_deref(),
            max_cases,
            &config.matched_upstream,
            &original_uri,
        )
        .await
        {
            should_record = true;
            upstream_base = config.matched_upstream.clone();
            case = Some(candidate_case);
            admitted_case_pattern = Some(case_pattern);
            case_guard = Some(guard);
        }
    }

    if let Some(case) = &case {
        state.configure_case_observation(
            case.id,
            &method,
            &original_uri,
            &request_body,
            started,
            Duration::from_millis(config.request_timeout_ms),
        );
        state.inner.active_cases.register_case_publication(case.id);
    }
    let case_guard = case_guard.map(std::sync::Arc::new);
    let stream_guard = case_guard.clone();
    let lifecycle_state = state.clone();
    let active_case_id = case.as_ref().map(|case| case.id);
    let (mut timeout_recovery, timeout_response) = match &case {
        Some(case) => {
            let (recovery, receiver) = recovery::TimeoutRecovery::new(
                state.clone(),
                case.clone(),
                u128::from(config.request_timeout_ms),
            );
            (Some(recovery), Some(receiver))
        }
        None => (None, None),
    };
    let request = async move {
        if !should_record && config.fallback_mode == HttpGatewayFallbackMode::FixedResponse {
            return build_fixed_response(
                config
                    .fixed_response
                    .as_ref()
                    .expect("validated fixed response configuration"),
            );
        }

        let case_request_record = case.as_ref().map(|_| CaseRequestRecord {
            timestamp: Utc::now(),
            client_addr: client_addr.clone(),
            method: method.to_string(),
            uri: original_uri.to_string(),
            api_pattern: admitted_case_pattern.clone(),
            authority: authority.clone(),
            matched_rule: matched_rule_name.clone(),
            upstream: upstream_base.clone(),
            headers: request_headers_for_record.clone(),
            body: capture_case_body(
                &request_body,
                state.config().recording.max_body_bytes,
                state.config().recording.decoded_body_limit(),
                Some(&request_headers),
            ),
            sse_observation: None,
            interaction: None,
        });

        let outbound_uri = match build_upstream_uri(&upstream_base, &original_uri) {
            Ok(uri) => uri,
            Err(err) => {
                return record_gateway_error(GatewayErrorContext {
                    state,
                    id,
                    client_addr,
                    method,
                    original_uri,
                    authority,
                    request_headers: request_headers_for_record,
                    request_body,
                    started,
                    request_started_at,
                    matched_rule: matched_rule_name.clone(),
                    case,
                    should_record,
                    target: Some(upstream_base.clone()),
                    err,
                })
                .await;
            }
        };

        let mut outbound = match build_upstream_request(
            &method,
            outbound_uri,
            request_body.clone(),
            &request_headers,
            config.preserve_host,
        ) {
            Ok(req) => req,
            Err(err) => {
                return record_gateway_error(GatewayErrorContext {
                    state,
                    id,
                    client_addr,
                    method,
                    original_uri,
                    authority,
                    request_headers: request_headers_for_record,
                    request_body,
                    started,
                    request_started_at,
                    matched_rule: matched_rule_name.clone(),
                    case,
                    should_record,
                    target: Some(upstream_base.clone()),
                    err,
                })
                .await;
            }
        };

        if should_record && config.record_streaming {
            response::prefer_uncompressed_stream(&mut outbound);
        }
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        let upstream_response = response::acquire(
            state.client(),
            outbound,
            request_timeout,
            timeout_recovery.as_mut(),
        )
        .await;

        let response::AcquiredResponse {
            status,
            headers: response_headers,
            body: response_body,
            deadline,
        } = match upstream_response {
            Ok(response) => response,
            Err(err) => {
                let timed_out = err.is::<tokio::time::error::Elapsed>();
                return record_gateway_error_with_status(
                    GatewayErrorContext {
                        state,
                        id,
                        client_addr,
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
                        request_started_at,
                        matched_rule: matched_rule_name.clone(),
                        case,
                        should_record,
                        target: Some(upstream_base.clone()),
                        err: if timed_out {
                            anyhow!(
                                "gateway upstream request timed out after {} ms",
                                config.request_timeout_ms
                            )
                        } else {
                            err
                        },
                    },
                    if timed_out {
                        StatusCode::GATEWAY_TIMEOUT
                    } else {
                        StatusCode::BAD_GATEWAY
                    },
                    timeout_recovery.as_ref().filter(|_| timed_out),
                )
                .await;
            }
        };
        if response::is_interaction(
            &response_headers,
            config.record_streaming && config.record_raw_streaming,
        ) {
            let stream = response_body;
            if let (Some(case), Some(guard)) = (case.clone(), stream_guard) {
                return interaction::adopt_response(
                    state,
                    case,
                    guard,
                    client_addr,
                    method,
                    original_uri,
                    admitted_case_pattern.unwrap_or_else(|| "/".to_owned()),
                    request_headers_for_record,
                    request_headers,
                    request_body,
                    upstream_base,
                    started,
                    request_started_at,
                    status,
                    response_headers,
                    stream,
                )
                .await;
            }
            let mut response = Response::new(stream.map_err(anyhow::Error::from).boxed_unsync());
            *response.status_mut() = status;
            *response.headers_mut() = response_headers;
            return response;
        }
        ordinary::forward(
            ordinary::CaptureContext {
                state,
                id,
                client_addr,
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                request_started_at,
                matched_rule: matched_rule_name,
                case,
                request_record: case_request_record,
                upstream: upstream_base,
                guard: stream_guard,
            },
            status,
            response_headers,
            response_body,
            deadline,
            timeout_recovery,
        )
        .await
    };

    match (case_guard, active_case_id) {
        (Some(case_guard), Some(case_id)) => {
            lifecycle::run_matched_request(
                lifecycle_state,
                case_id,
                case_guard,
                started,
                timeout_response.expect("matched case timeout response"),
                request,
            )
            .await
        }
        _ => request.await,
    }
}

struct GatewayErrorContext {
    state: AppState,
    id: Uuid,
    client_addr: Option<String>,
    method: Method,
    original_uri: Uri,
    authority: Option<String>,
    request_headers: HeaderMapSnapshot,
    request_body: Bytes,
    started: Instant,
    request_started_at: chrono::DateTime<Utc>,
    matched_rule: Option<String>,
    case: Option<CaseContext>,
    should_record: bool,
    target: Option<String>,
    err: anyhow::Error,
}

async fn record_gateway_error(ctx: GatewayErrorContext) -> Response<GatewayBody> {
    record_gateway_error_with_status(ctx, StatusCode::BAD_GATEWAY, None).await
}

async fn record_gateway_error_with_status(
    ctx: GatewayErrorContext,
    response_status: StatusCode,
    recovery: Option<&recovery::TimeoutRecovery>,
) -> Response<GatewayBody> {
    let error = format!("{:#}", ctx.err);
    let drain_invalidation = if let Some(case) = &ctx.case {
        ctx.state.drain_active_case_dependencies(case.id).await
    } else {
        None
    };
    if let Some(recovery) = recovery {
        recovery
            .dependencies_drained(drain_invalidation.as_ref())
            .await;
    }
    if let Some(case) = &ctx.case
        && let Err(err) = finalize_owned_http_case(
            ctx.state.recorder(),
            &ctx.state
                .inner
                .active_cases
                .register_case_publication(case.id)
                .expect("failed HTTP request retains case publication ownership"),
            case,
            CaseRequestRecord {
                timestamp: Utc::now(),
                client_addr: ctx.client_addr.clone(),
                method: ctx.method.to_string(),
                uri: ctx.original_uri.to_string(),
                api_pattern: None,
                authority: ctx.authority.clone(),
                matched_rule: ctx.matched_rule.clone(),
                upstream: ctx.target.clone().unwrap_or_default(),
                headers: ctx.request_headers.clone(),
                body: capture_case_body(
                    &ctx.request_body,
                    ctx.state.config().recording.max_body_bytes,
                    ctx.state.config().recording.decoded_body_limit(),
                    None,
                ),
                sse_observation: None,
                interaction: None,
            },
            CaseResponseRecord {
                timestamp: Utc::now(),
                matched_rule: ctx.matched_rule.clone(),
                upstream: ctx.target.clone().unwrap_or_default(),
                status: None,
                headers: None,
                body: None,
                duration_ms: ctx.started.elapsed().as_millis(),
                error: Some(error.clone()),
                sse_observation: None,
                interaction: None,
            },
            ctx.state
                .active_case_invalidation(case.id)
                .or(drain_invalidation),
        )
        .await
    {
        warn!(error = %err, case_id = %case.id, "failed to finalize failed HTTP gateway case");
    }

    if ctx.should_record {
        let event = HttpExchangeEvent {
            outcome: crate::DependencyExchangeOutcome::Response,
            id: ctx.id,
            timestamp: Utc::now(),
            request_started_at: ctx.request_started_at,
            client_addr: ctx.client_addr.clone(),
            scheme: "http_gateway".to_string(),
            method: ctx.method.to_string(),
            uri: ctx.original_uri.to_string(),
            authority: ctx.authority.clone(),
            request_headers: with_gateway_headers(
                ctx.request_headers,
                ctx.matched_rule.as_deref(),
                ctx.target.as_deref().unwrap_or(""),
            ),
            request_body: capture_body(
                &ctx.request_body,
                ctx.state.config().recording.max_body_bytes,
            ),
            response_status: None,
            response_headers: None,
            response_body: None,
            response_stream: None,
            discovered_tcp_targets: Vec::new(),
            duration_ms: ctx.started.elapsed().as_millis(),
            error: Some(error.clone()),
        };
        if let Err(record_err) = ctx
            .state
            .recorder()
            .record(RecorderEvent::HttpExchange(event))
            .await
        {
            warn!(error = %record_err, "failed to record failed HTTP gateway exchange");
        }
    }

    if let Err(record_err) = ctx
        .state
        .recorder()
        .record(RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            connection_id: None,
            timestamp: Utc::now(),
            protocol: "http_gateway".to_string(),
            client_addr: ctx.client_addr,
            target: ctx.target,
            error: error.clone(),
        }))
        .await
    {
        warn!(error = %record_err, "failed to record HTTP gateway proxy error");
    }

    simple_response(response_status, &error)
}

fn with_gateway_headers(
    mut headers: HeaderMapSnapshot,
    matched_rule: Option<&str>,
    upstream: &str,
) -> HeaderMapSnapshot {
    headers
        .entry("x-recorder-gateway-rule".to_string())
        .or_default()
        .push(matched_rule.unwrap_or("unknown").to_string());
    headers
        .entry("x-recorder-gateway-upstream".to_string())
        .or_default()
        .push(upstream.to_string());
    headers
}
