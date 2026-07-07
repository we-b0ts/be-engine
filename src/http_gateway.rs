use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST};
use hyper::http::uri::{Authority, PathAndQuery, Scheme};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::{
    DEFAULT_HTTP_GATEWAY_CASE_URI_SEGMENTS, HttpGatewayConfig, HttpGatewayReadyConfig,
    HttpGatewayRuleConfig,
};
use crate::process_lookup::{lookup_listening_process, process_label};
use crate::recorder::{
    CaseBodyCapture, CaseContext, HeaderMapSnapshot, HttpExchangeEvent, ProxyErrorEvent,
    RecorderEvent, capture_body, capture_case_body, redact_headers,
};
use crate::{ActiveCaseGuard, ActiveCaseRejection, AppState, ProxyClient};

type GatewayBody = BoxBody<Bytes, Infallible>;

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config().http_gateway.clone();
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind HTTP gateway {}", config.listen))?;
    info!(
        listen = %config.listen,
        matched_upstream = %config.matched_upstream,
        fallback_upstream = %config.fallback_upstream,
        "HTTP gateway listening"
    );

    if config.ready.enabled {
        let ready_state = state.clone();
        let ready_config = config.clone();
        tokio::spawn(async move {
            run_ready_probe(ready_state, ready_config).await;
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

async fn run_ready_probe(state: AppState, config: HttpGatewayConfig) {
    let interval = Duration::from_millis(config.ready.interval_ms.max(1));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!(
        upstream = %config.matched_upstream,
        path = %config.ready.path,
        success_status = config.ready.success_status,
        interval_ms = config.ready.interval_ms.max(1),
        "HTTP gateway ready probe started"
    );

    while state.is_bootstrap_open() {
        ticker.tick().await;
        match probe_ready_once(&state, &config.matched_upstream, &config.ready).await {
            Ok(status) if status == config.ready.success_status => {
                state.close_bootstrap("http_gateway.ready");
                info!(
                    upstream = %config.matched_upstream,
                    path = %config.ready.path,
                    status,
                    "HTTP gateway ready probe succeeded"
                );
                return;
            }
            Ok(status) => {
                debug!(
                    upstream = %config.matched_upstream,
                    path = %config.ready.path,
                    status,
                    expected = config.ready.success_status,
                    "HTTP gateway ready probe did not match"
                );
            }
            Err(err) => {
                debug!(
                    upstream = %config.matched_upstream,
                    path = %config.ready.path,
                    error = %err,
                    "HTTP gateway ready probe failed"
                );
            }
        }
    }

    info!("HTTP gateway ready probe stopped because bootstrap is already closed");
}

async fn probe_ready_once(
    state: &AppState,
    upstream_base: &str,
    ready: &HttpGatewayReadyConfig,
) -> Result<u16> {
    let ready_uri = ready_probe_path_uri(&ready.path)?;
    let outbound_uri = build_upstream_uri(upstream_base, &ready_uri)?;
    let outbound = build_upstream_request(
        &Method::GET,
        outbound_uri,
        Bytes::new(),
        &HeaderMap::new(),
        false,
    )?;
    let response = send_upstream(state.client(), outbound)
        .await
        .context("HTTP gateway ready probe request failed")?;
    let status = response.status().as_u16();
    let _ = response.into_body().collect().await;
    Ok(status)
}

fn ready_probe_path_uri(path: &str) -> Result<Uri> {
    let trimmed = path.trim();
    let normalized = if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    };
    normalized
        .parse::<Uri>()
        .with_context(|| format!("invalid HTTP gateway ready path {path}"))
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
    let request_headers = req.headers().clone();
    let request_headers_for_record =
        redact_headers(&request_headers, &state.config().recording.redact_headers);
    let authority = request_authority(&original_uri, &request_headers);
    let matched_rule = match_rule(&config.rules, &method, &original_uri, &request_headers);
    let matched_rule_name = matched_rule.as_ref().map(|rule| rule.name.clone());
    let candidate_case = matched_rule.as_ref().map(|rule| CaseContext {
        id,
        rule_name: rule.name.clone(),
        uri_group: case_uri_group(&original_uri, rule.case_uri_segments),
    });
    let mut should_record = false;
    let mut case = None;
    let mut upstream_base = config.fallback_upstream.clone();
    let mut _case_guard = None;

    if let Some(candidate_case) = candidate_case {
        match try_register_case_for_upstream(&state, &candidate_case, &config.matched_upstream) {
            Ok(guard) => {
                should_record = true;
                upstream_base = config.matched_upstream.clone();
                case = Some(candidate_case);
                _case_guard = Some(guard);
            }
            Err(reason) => {
                info!(
                    reason = %active_case_rejection_reason(reason),
                    matched_rule = matched_rule_name.as_deref().unwrap_or("unknown"),
                    uri = %original_uri,
                    "HTTP gateway matched request sent to fallback"
                );
            }
        }
    }

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

    if let Some(case) = &case
        && let Err(err) = write_case_request(
            &state,
            case,
            CaseRequestRecord {
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
                    Some(&request_headers),
                ),
            },
        )
        .await
    {
        warn!(error = %err, case_id = %case.id, "failed to write HTTP gateway case request");
    }

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
            let response_headers = upstream_response.headers().clone();
            let response_headers_for_record =
                redact_headers(&response_headers, &state.config().recording.redact_headers);
            let body_bytes = match upstream_response.into_body().collect().await {
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

            if should_record {
                let event = HttpExchangeEvent {
                    id,
                    timestamp: Utc::now(),
                    client_addr: client_addr.clone(),
                    client_process: None,
                    scheme: "http_gateway".to_string(),
                    method: method.to_string(),
                    uri: original_uri.to_string(),
                    authority: authority.clone(),
                    request_headers: with_gateway_headers(
                        request_headers_for_record,
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

            if let Some(case) = &case
                && let Err(err) = write_case_response(
                    &state,
                    case,
                    CaseResponseRecord {
                        timestamp: Utc::now(),
                        matched_rule: matched_rule_name.clone(),
                        upstream: upstream_base.clone(),
                        status: Some(status.as_u16()),
                        headers: Some(response_headers_for_record.clone()),
                        body: Some(capture_case_body(
                            &body_bytes,
                            state.config().recording.max_body_bytes,
                            Some(&response_headers),
                        )),
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                    },
                )
                .await
            {
                warn!(error = %err, case_id = %case.id, "failed to write HTTP gateway case response");
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
}

async fn send_upstream(
    client: &ProxyClient,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    client.request(request).await
}

#[derive(Serialize)]
struct CaseRequestRecord {
    timestamp: chrono::DateTime<Utc>,
    client_addr: Option<String>,
    method: String,
    uri: String,
    authority: Option<String>,
    matched_rule: Option<String>,
    upstream: String,
    headers: HeaderMapSnapshot,
    body: CaseBodyCapture,
}

#[derive(Serialize)]
struct CaseResponseRecord {
    timestamp: chrono::DateTime<Utc>,
    matched_rule: Option<String>,
    upstream: String,
    status: Option<u16>,
    headers: Option<HeaderMapSnapshot>,
    body: Option<CaseBodyCapture>,
    duration_ms: u128,
    error: Option<String>,
}

async fn write_case_request(
    state: &AppState,
    case: &CaseContext,
    record: CaseRequestRecord,
) -> Result<()> {
    state
        .recorder()
        .write_case_json(case, "request.json", &record)
        .await
}

async fn write_case_response(
    state: &AppState,
    case: &CaseContext,
    record: CaseResponseRecord,
) -> Result<()> {
    state
        .recorder()
        .write_case_json(case, "expected-response.json", &record)
        .await
}

fn try_register_case_for_upstream(
    state: &AppState,
    case: &CaseContext,
    upstream_base: &str,
) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
    let process = upstream_socket_addr(upstream_base).and_then(lookup_listening_process);
    let guard = state
        .try_register_active_case(case.clone(), process.as_ref().map(|process| process.pid))?;
    match &process {
        Some(process) => {
            info!(
                case_id = %case.id,
                rule = %case.rule_name,
                upstream = %upstream_base,
                process = %process_label(process),
                "registered active HTTP gateway case"
            );
        }
        None => {
            info!(
                case_id = %case.id,
                rule = %case.rule_name,
                upstream = %upstream_base,
                "registered active HTTP gateway case without upstream process match"
            );
        }
    }
    Ok(guard)
}

fn active_case_rejection_reason(reason: ActiveCaseRejection) -> &'static str {
    match reason {
        ActiveCaseRejection::NotReady => "not_ready",
        ActiveCaseRejection::Busy => "busy",
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
    let error = ctx.err.to_string();
    if let Some(case) = &ctx.case
        && let Err(err) = write_case_response(
            &ctx.state,
            case,
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
        )
        .await
    {
        warn!(error = %err, case_id = %case.id, "failed to write HTTP gateway failed case response");
    }

    if ctx.should_record {
        let event = HttpExchangeEvent {
            id: ctx.id,
            timestamp: Utc::now(),
            client_addr: ctx.client_addr.clone(),
            client_process: None,
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
            client_process: None,
            target: ctx.target,
            error: error.clone(),
        }))
        .await
    {
        warn!(error = %record_err, "failed to record HTTP gateway proxy error");
    }

    simple_response(StatusCode::BAD_GATEWAY, &error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedHttpGatewayRule {
    name: String,
    case_uri_segments: usize,
}

fn match_rule(
    rules: &[HttpGatewayRuleConfig],
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Option<MatchedHttpGatewayRule> {
    if rules.is_empty() {
        return Some(MatchedHttpGatewayRule {
            name: "default".to_string(),
            case_uri_segments: DEFAULT_HTTP_GATEWAY_CASE_URI_SEGMENTS,
        });
    }

    rules
        .iter()
        .find(|rule| rule_matches(rule, method, uri, headers))
        .map(|rule| MatchedHttpGatewayRule {
            name: rule.name.clone().unwrap_or_else(|| "unnamed".to_string()),
            case_uri_segments: rule.case_uri_segments,
        })
}

fn rule_matches(
    rule: &HttpGatewayRuleConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> bool {
    if !rule.methods.is_empty()
        && !rule
            .methods
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(method.as_str()))
    {
        return false;
    }

    if !rule.hosts.is_empty() {
        let host = request_authority(uri, headers).unwrap_or_default();
        if !rule
            .hosts
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&host))
        {
            return false;
        }
    }

    if !rule.path_prefixes.is_empty()
        && !rule
            .path_prefixes
            .iter()
            .any(|prefix| path_matches_prefix(uri.path(), prefix))
    {
        return false;
    }

    rule.headers.iter().all(|(name, expected)| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| actual == expected)
    })
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    let normalized = prefix.trim_end_matches('/');
    path == normalized || path.starts_with(&format!("{normalized}/"))
}

fn case_uri_group(uri: &Uri, segment_count: usize) -> Option<String> {
    if segment_count == 0 {
        return None;
    }

    let group = uri
        .path()
        .split('/')
        .filter(|segment| !segment.is_empty())
        .take(segment_count)
        .collect::<Vec<_>>()
        .join("-");

    Some(if group.is_empty() {
        "root".to_string()
    } else {
        group
    })
}

fn upstream_socket_addr(base: &str) -> Option<SocketAddr> {
    let uri = base.parse::<Uri>().ok()?;
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority()?;
    let port = authority.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    let ip = if authority.host().eq_ignore_ascii_case("localhost") {
        IpAddr::from([127, 0, 0, 1])
    } else {
        authority.host().parse::<IpAddr>().ok()?
    };
    Some(SocketAddr::new(ip, port))
}

fn build_upstream_uri(base: &str, original_uri: &Uri) -> Result<Uri> {
    let base = base
        .parse::<Uri>()
        .with_context(|| format!("invalid gateway upstream URI {base}"))?;
    let scheme = base
        .scheme()
        .cloned()
        .ok_or_else(|| anyhow!("gateway upstream URI missing scheme"))?;
    let authority = base
        .authority()
        .cloned()
        .ok_or_else(|| anyhow!("gateway upstream URI missing authority"))?;
    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));

    let mut parts = hyper::http::uri::Parts::default();
    parts.scheme = Some(Scheme::try_from(scheme.as_str())?);
    parts.authority = Some(Authority::try_from(authority.as_str())?);
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct gateway upstream URI")
}

fn build_upstream_request(
    method: &Method,
    uri: Uri,
    body: Bytes,
    source_headers: &HeaderMap,
    preserve_host: bool,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder().method(method).uri(uri.clone());
    let headers = builder.headers_mut().expect("request builder headers");
    for (name, value) in source_headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if !preserve_host && name == HOST {
            continue;
        }
        headers.append(name, value.clone());
    }
    if !preserve_host && let Some(authority) = uri.authority() {
        headers.insert(HOST, authority.as_str().parse()?);
    }
    builder
        .body(Full::new(body))
        .context("failed to build gateway upstream request")
}

fn build_downstream_response(
    status: StatusCode,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<GatewayBody> {
    let mut builder = Response::builder().status(status);
    let out_headers = builder.headers_mut().expect("response builder headers");
    for (name, value) in headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out_headers.append(name, value.clone());
    }
    builder
        .body(boxed_body(body))
        .unwrap_or_else(|_| simple_response(StatusCode::BAD_GATEWAY, "failed to build response"))
}

fn simple_response(status: StatusCode, body: &str) -> Response<GatewayBody> {
    Response::builder()
        .status(status)
        .body(boxed_body(Bytes::copy_from_slice(body.as_bytes())))
        .expect("valid static response")
}

fn boxed_body(bytes: Bytes) -> GatewayBody {
    Full::new(bytes).boxed()
}

fn request_authority(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority().map(ToString::to_string).or_else(|| {
        headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    })
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

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || name.eq_ignore_ascii_case(CONNECTION.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppConfig, HttpGatewayReadyConfig};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn matches_rule_by_host_method_path_and_header() {
        let rule = HttpGatewayRuleConfig {
            name: Some("api".to_string()),
            hosts: vec!["api.example.com".to_string()],
            methods: vec!["POST".to_string()],
            path_prefixes: vec!["/v1/".to_string()],
            headers: [("x-record".to_string(), "yes".to_string())].into(),
            ..Default::default()
        };
        let request = Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header(HOST, "api.example.com")
            .header("x-record", "yes")
            .body(())
            .unwrap();

        assert!(rule_matches(
            &rule,
            request.method(),
            request.uri(),
            request.headers()
        ));
    }

    #[test]
    fn builds_target_uri_from_original_path() {
        let uri =
            build_upstream_uri("http://127.0.0.1:9000", &"/hello?a=1".parse().unwrap()).unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:9000/hello?a=1");
    }

    #[test]
    fn builds_ready_probe_path_uri() {
        assert_eq!(ready_probe_path_uri("").unwrap().to_string(), "/");
        assert_eq!(
            ready_probe_path_uri("healthz").unwrap().to_string(),
            "/healthz"
        );
        assert_eq!(
            ready_probe_path_uri(" /ready?probe=1 ")
                .unwrap()
                .to_string(),
            "/ready?probe=1"
        );
    }

    #[tokio::test]
    async fn ready_probe_closes_bootstrap_on_success_status() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.http_gateway.matched_upstream = format!("http://{upstream_addr}");
        config.http_gateway.ready = HttpGatewayReadyConfig {
            enabled: true,
            path: "/ready".to_string(),
            success_status: 200,
            interval_ms: 1,
        };
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");

        let state = AppState::new(config).await.unwrap();
        assert!(state.is_bootstrap_open());

        let ready_config = state.config().http_gateway.clone();
        tokio::time::timeout(
            Duration::from_secs(1),
            run_ready_probe(state.clone(), ready_config),
        )
        .await
        .unwrap();

        assert!(!state.is_bootstrap_open());
    }

    #[test]
    fn builds_case_uri_group_from_path_segments() {
        assert_eq!(
            case_uri_group(&"/api/users/list?x=1".parse().unwrap(), 2).as_deref(),
            Some("api-users")
        );
        assert_eq!(
            case_uri_group(&"/api/users/list".parse().unwrap(), 1).as_deref(),
            Some("api")
        );
        assert_eq!(case_uri_group(&"/api/users/list".parse().unwrap(), 0), None);
        assert_eq!(
            case_uri_group(&"/".parse().unwrap(), 2).as_deref(),
            Some("root")
        );
    }
}
