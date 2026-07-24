use std::convert::Infallible;
use std::time::Instant;

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
use crate::http::rewrite::{self, RewriteInput};
use crate::recorder::http::case::{CaseRequestRecord, CaseResponseRecord, finalize_http_case};
use crate::recorder::{
    CaseContext, HeaderMapSnapshot, HttpExchangeEvent, ProxyErrorEvent, RecorderEvent,
    capture_body, capture_case_body, redact_headers,
};

mod admission;
mod lifecycle;
mod ready;
pub(crate) mod rules;
pub(crate) mod transport;

use admission::try_admit_case;
use rules::{RuleDecision, evaluate_request, request_authority, resolve_case_group};
use transport::{
    GatewayBody, build_downstream_response, build_fixed_response, build_upstream_request,
    build_upstream_uri, send_upstream, simple_response,
};

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config().http_gateway.clone();
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind HTTP gateway {}", config.listen))?;
    info!(
        listen = %config.listen,
        matched_upstream = %config.matched_upstream,
        fallback_upstream = %config.fallback_upstream,
        fallback_mode = ?config.fallback_mode,
        "HTTP gateway listening"
    );

    if config.ready.enabled {
        let ready_state = state.clone();
        let ready_config = config.clone();
        tokio::spawn(async move {
            ready::run(ready_state, ready_config).await;
        });
    }

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept HTTP gateway client")?;
        let state = state.clone();
        let config = config.clone();
        tokio::spawn(async move {
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

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
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
    let request_headers_for_record =
        redact_headers(&request_headers, &state.config().recording.redact_headers);
    let authority = request_authority(&original_uri, &request_headers);
    let matched_rule = match evaluate_request(
        &config.verified_excludes,
        &config.exclude_rules,
        &config.rules,
        &method,
        &original_uri,
        &request_headers,
    ) {
        RuleDecision::Matched(rule) => Some(rule),
        RuleDecision::Excluded { name } => {
            info!(exclude_rule = %name, uri = %original_uri, "HTTP gateway request excluded from matching");
            None
        }
        RuleDecision::Unmatched => None,
    };
    let matched_rule_name = matched_rule.as_ref().map(|rule| rule.name.clone());
    let candidate_case = matched_rule.as_ref().map(|rule| {
        let group = resolve_case_group(&original_uri, &rule.case_path_patterns);
        let max_cases = config.case_limits.limit_for(&group.pattern);
        (
            CaseContext {
                id,
                rule_name: rule.name.clone(),
                uri_group: Some(group.directory),
            },
            group.pattern,
            max_cases,
        )
    });
    let mut should_record = false;
    let mut case = None;
    let mut upstream_base = config.fallback_upstream.clone();
    let mut case_guard = None;

    if let Some((candidate_case, case_pattern, max_cases)) = candidate_case
        && let Some(guard) = try_admit_case(
            &state,
            &candidate_case,
            &case_pattern,
            max_cases,
            &config.matched_upstream,
            &original_uri,
        )
        .await
    {
        should_record = true;
        upstream_base = config.matched_upstream.clone();
        case = Some(candidate_case);
        case_guard = Some(guard);
    }

    let lifecycle_state = state.clone();
    let active_case_id = case.as_ref().map(|case| case.id);
    let request = async move {
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
                    matched_rule: matched_rule_name.clone(),
                    case,
                    should_record,
                    target: Some(upstream_base.clone()),
                    err: anyhow!("failed to read gateway request body: {err}"),
                })
                .await;
            }
        };

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
                    matched_rule: matched_rule_name.clone(),
                    case,
                    should_record,
                    target: Some(upstream_base.clone()),
                    err,
                })
                .await;
            }
        };

        let outbound = match build_upstream_request(
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
                    matched_rule: matched_rule_name.clone(),
                    case,
                    should_record,
                    target: Some(upstream_base.clone()),
                    err,
                })
                .await;
            }
        };

        match send_upstream(state.client(), outbound).await {
            Ok(upstream_response) => {
                let status = upstream_response.status();
                let mut response_headers = upstream_response.headers().clone();
                let mut body_bytes = match upstream_response.into_body().collect().await {
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
                            request_body,
                            started,
                            matched_rule: matched_rule_name.clone(),
                            case,
                            should_record,
                            target: Some(upstream_base.clone()),
                            err: anyhow!("failed to read gateway upstream response body: {err}"),
                        })
                        .await;
                    }
                };
                let mut discovered_tcp_targets = Vec::new();
                match rewrite::apply(
                    &state.config().http_response_rewrite,
                    state.dns_registry(),
                    state.kubectl_proxy_manager(),
                    state.ca().ca_cert_pem_ref(),
                    RewriteInput {
                        method: &method,
                        uri: &original_uri,
                        authority: authority.as_deref(),
                        status,
                        headers: &response_headers,
                        body: &body_bytes,
                    },
                )
                .await
                {
                    Ok(Some(rewritten)) => {
                        response_headers = rewritten.headers;
                        body_bytes = rewritten.body;
                        discovered_tcp_targets = rewritten.discovered_tcp_targets;
                    }
                    Ok(None) => {}
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
                            matched_rule: matched_rule_name.clone(),
                            case,
                            should_record,
                            target: Some(upstream_base.clone()),
                            err,
                        })
                        .await;
                    }
                }
                let response_headers_for_record =
                    redact_headers(&response_headers, &state.config().recording.redact_headers);

                if should_record {
                    let event = HttpExchangeEvent {
                        id,
                        timestamp: Utc::now(),
                        client_addr: client_addr.clone(),
                        scheme: "http_gateway".to_string(),
                        method: method.to_string(),
                        uri: original_uri.to_string(),
                        authority: authority.clone(),
                        request_headers: with_gateway_headers(
                            request_headers_for_record.clone(),
                            matched_rule_name.as_deref(),
                            &upstream_base,
                        ),
                        request_body: capture_body(
                            &request_body,
                            state.config().recording.max_body_bytes,
                        ),
                        response_status: Some(status.as_u16()),
                        response_headers: Some(response_headers_for_record.clone()),
                        response_body: Some(capture_body(
                            &body_bytes,
                            state.config().recording.max_body_bytes,
                        )),
                        discovered_tcp_targets,
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                    };
                    if let Err(err) = state
                        .recorder()
                        .record(RecorderEvent::HttpExchange(event))
                        .await
                    {
                        warn!(error = %err, "failed to record HTTP gateway exchange");
                    }
                }

                let drain_invalidation = if let Some(case) = &case {
                    state.drain_active_case_dependencies(case.id).await
                } else {
                    None
                };
                if let (Some(case), Some(request_record)) = (&case, case_request_record)
                    && let Err(err) = finalize_http_case(
                        state.recorder(),
                        case,
                        request_record,
                        CaseResponseRecord {
                            timestamp: Utc::now(),
                            matched_rule: matched_rule_name.clone(),
                            upstream: upstream_base.clone(),
                            status: Some(status.as_u16()),
                            headers: Some(response_headers_for_record.clone()),
                            body: Some(capture_case_body(
                                &body_bytes,
                                state.config().recording.max_body_bytes,
                                state.config().recording.decoded_body_limit(),
                                Some(&response_headers),
                            )),
                            duration_ms: started.elapsed().as_millis(),
                            error: None,
                        },
                        state
                            .active_case_invalidation(case.id)
                            .or(drain_invalidation),
                    )
                    .await
                {
                    warn!(error = %err, case_id = %case.id, "failed to finalize HTTP gateway case");
                }

                build_downstream_response(status, &response_headers, body_bytes)
            }
            Err(err) => {
                record_gateway_error(GatewayErrorContext {
                    state,
                    id,
                    client_addr,
                    method,
                    original_uri,
                    authority,
                    request_headers: request_headers_for_record,
                    request_body,
                    started,
                    matched_rule: matched_rule_name.clone(),
                    case,
                    should_record,
                    target: Some(upstream_base.clone()),
                    err: anyhow!("gateway upstream request failed: {err}"),
                })
                .await
            }
        }
    };

    match (case_guard, active_case_id) {
        (Some(case_guard), Some(case_id)) => {
            lifecycle::run_matched_request(lifecycle_state, case_id, case_guard, started, request)
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
    matched_rule: Option<String>,
    case: Option<CaseContext>,
    should_record: bool,
    target: Option<String>,
    err: anyhow::Error,
}

async fn record_gateway_error(ctx: GatewayErrorContext) -> Response<GatewayBody> {
    let error = format!("{:#}", ctx.err);
    let drain_invalidation = if let Some(case) = &ctx.case {
        ctx.state.drain_active_case_dependencies(case.id).await
    } else {
        None
    };
    if let Some(case) = &ctx.case
        && let Err(err) = finalize_http_case(
            ctx.state.recorder(),
            case,
            CaseRequestRecord {
                timestamp: Utc::now(),
                client_addr: ctx.client_addr.clone(),
                method: ctx.method.to_string(),
                uri: ctx.original_uri.to_string(),
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
            id: ctx.id,
            timestamp: Utc::now(),
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

    simple_response(StatusCode::BAD_GATEWAY, &error)
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
