//! Session admission and transparent transport for bounded primary interactions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, Uri, body::Incoming};
use tokio::sync::{Notify, watch};
use uuid::Uuid;

use super::{
    admission::try_admit_case,
    rules::{RuleDecision, evaluate_request, resolve_case_group},
    transport::{self, GatewayBody, simple_response},
};
use crate::interaction::{
    model::{EndReason, Protocol},
    observation::Observation,
};
use crate::recorder::{CaseContext, PrimaryCaseDescriptor};
use crate::{ActiveCaseGuard, AppState, config::HttpGatewayConfig};

mod body;
mod finish;
mod polling;
mod stream;
mod transport_lifetime;
mod websocket;

#[cfg(test)]
mod tests;

pub(crate) struct Sessions {
    by_sid: Mutex<HashMap<String, Arc<Session>>>,
    active: Mutex<HashMap<Uuid, std::sync::Weak<Session>>>,
    source_stop: watch::Sender<bool>,
}

impl Default for Sessions {
    fn default() -> Self {
        Self {
            by_sid: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
            source_stop: watch::channel(false).0,
        }
    }
}

pub(super) struct Session {
    state: AppState,
    case: CaseContext,
    observation: Mutex<Observation>,
    started: Instant,
    close: watch::Sender<Option<EndReason>>,
    changed: Notify,
    upstream: String,
    original_uri: Uri,
    method: hyper::Method,
    request_headers: hyper::HeaderMap,
    response: Mutex<Option<(u16, hyper::HeaderMap)>>,
    sid: Mutex<Option<String>>,
    active_io: std::sync::atomic::AtomicUsize,
    transports: Mutex<Vec<tokio::task::AbortHandle>>,
    upgraded: std::sync::atomic::AtomicBool,
    eio_closed: std::sync::atomic::AtomicBool,
}

pub(super) type SessionRef = Arc<Session>;

impl Session {
    fn observe_input(&self, message: crate::interaction::model::WireMessage) -> Result<()> {
        let now = self.now();
        let dependency = self
            .state
            .inner
            .active_cases
            .dependency_activity(self.case.id);
        let mut observation = self
            .observation
            .lock()
            .expect("interaction observation poisoned");
        if let Some((in_flight, last)) = dependency {
            let activity = if in_flight > 0 {
                now
            } else {
                last.saturating_duration_since(self.started)
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX)
            };
            observation.dependency_activity(activity);
        }
        observation.input(message, now)?;
        Ok(())
    }
    fn now(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
    fn request_close(&self, reason: EndReason) {
        self.close.send_replace(Some(reason));
        self.changed.notify_one();
    }
    fn closing(&self) -> Option<EndReason> {
        *self.close.borrow()
    }
}

pub(super) fn query(uri: &Uri, name: &str) -> Option<String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Only upgrade/session protocols are fixed before dispatch. HTTP stream
/// negotiation is resolved from the response Content-Type, not the Accept offer.
pub(crate) fn request_protocol(req: &Request<Incoming>) -> Option<Protocol> {
    let socket = req
        .uri()
        .path()
        .trim_end_matches('/')
        .ends_with("/socket.io");
    if (socket && query(req.uri(), "EIO").is_some())
        || (query(req.uri(), "EIO").as_deref() == Some("4")
            && query(req.uri(), "transport").is_some())
    {
        return Some(Protocol::SocketIo);
    }
    if is_websocket(req) {
        return Some(Protocol::WebSocket);
    }
    None
}

pub(super) fn response_protocol(headers: &hyper::HeaderMap) -> Option<Protocol> {
    crate::interaction::stream::response_protocol(headers)
}

pub(crate) async fn handle(
    mut req: Request<Incoming>,
    state: AppState,
    config: HttpGatewayConfig,
    client_addr: Option<String>,
    protocol: Protocol,
) -> Response<GatewayBody> {
    if protocol == Protocol::SocketIo
        && crate::interaction::socketio::classify_request(
            req.method().as_str(),
            &req.uri().to_string(),
            is_websocket(&req),
        )
        .is_err()
    {
        return simple_response(
            StatusCode::BAD_REQUEST,
            "invalid or unsupported Engine.IO transport",
        );
    }
    if protocol == Protocol::SocketIo
        && let Some(sid) = query(req.uri(), "sid")
    {
        let session = state
            .inner
            .interactions
            .by_sid
            .lock()
            .expect("interaction sessions poisoned")
            .get(&sid)
            .cloned();
        return match session {
            Some(session) if session.closing().is_none() => {
                dispatch(req, session, false).await.unwrap_or_else(|_| {
                    simple_response(StatusCode::BAD_GATEWAY, "interaction transport failed")
                })
            }
            _ => simple_response(
                StatusCode::BAD_REQUEST,
                "unknown or closed recording session",
            ),
        };
    }
    let uri = req.uri().clone();
    let method = req.method().clone();
    let matched = match evaluate_request(
        &config.exclude_rules,
        &config.rules,
        &method,
        &uri.path().parse::<Uri>().expect("validated URI path"),
        req.headers(),
    ) {
        RuleDecision::Matched(rule)
            if config.record_streaming && state.should_record_api(&method, &uri) =>
        {
            Some(rule)
        }
        _ => None,
    };
    let Some(rule) = matched else {
        return passthrough(req, &state, &config).await;
    };
    let policy = config.interaction_policy(protocol);
    let observation = match Observation::new(protocol, policy.clone()) {
        Ok(observation) => observation,
        Err(_) => {
            return simple_response(
                StatusCode::BAD_REQUEST,
                "interaction protocol requires an explicit completion profile",
            );
        }
    };
    let group = state.recording_api_pattern(&method, &uri).map_or_else(
        || resolve_case_group(&uri, &config.case_path_patterns),
        |pattern| resolve_case_group(&uri, &[pattern.to_owned()]),
    );
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: rule.name,
        uri_group: Some(group.directory),
    };
    let started = Instant::now();
    let api = state
        .recording_api_pattern(&method, &uri)
        .map(|pattern| format!("{method} {pattern}"));
    let Some(guard) = try_admit_case(
        &state,
        &case,
        &PrimaryCaseDescriptor::http(method.as_str(), &group.pattern),
        api.as_deref(),
        config.per_api_case_limits.limit_for(&group.pattern),
        &config.matched_upstream,
        &uri,
    )
    .await
    else {
        return passthrough(req, &state, &config).await;
    };
    let request_headers = match state.recorder().capture_request_headers(req.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            return simple_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to protect interaction headers",
            );
        }
    };
    let upgrade = if is_websocket(&req) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let (parts, body) = req.into_parts();
    let body = match tokio::time::timeout(
        std::time::Duration::from_millis(
            policy.request_timeout_ms.min(
                policy
                    .max_duration_ms
                    .saturating_sub(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
            ),
        ),
        Limited::new(body, state.config().recording.max_body_bytes).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        _ => {
            let _ = state
                .recorder()
                .fail_case(
                    &case,
                    "interaction_input_error",
                    "initial request body was not captured completely",
                )
                .await;
            return simple_response(StatusCode::BAD_REQUEST, "interaction input incomplete");
        }
    };
    state.configure_case_observation(
        case.id,
        &method,
        &uri,
        &body,
        started,
        std::time::Duration::from_millis(policy.max_duration_ms),
    );
    let (close, _) = watch::channel(None);
    let session = Arc::new(Session {
        state: state.clone(),
        case,
        observation: Mutex::new(observation),
        started,
        close,
        changed: Notify::new(),
        upstream: config.matched_upstream.clone(),
        original_uri: uri.clone(),
        method: method.clone(),
        request_headers: parts.headers.clone(),
        response: Mutex::new(None),
        sid: Mutex::new(None),
        active_io: std::sync::atomic::AtomicUsize::new(0),
        transports: Mutex::new(Vec::new()),
        upgraded: std::sync::atomic::AtomicBool::new(false),
        eio_closed: std::sync::atomic::AtomicBool::new(false),
    });
    let meta = finish::RequestMeta {
        timestamp: Utc::now(),
        method: method.to_string(),
        uri: uri.to_string(),
        api_pattern: group.pattern,
        headers: request_headers,
        raw_headers: parts.headers.clone(),
        body: body.clone(),
        client_addr,
    };
    let mut request = Request::from_parts(parts, Full::new(body));
    if let Some(upgrade) = upgrade {
        request
            .extensions_mut()
            .insert(websocket::DownstreamUpgrade(Arc::new(Mutex::new(Some(
                upgrade,
            )))));
    }
    finish::spawn(session.clone(), guard, meta);
    let result = dispatch_full(request, session.clone(), true).await;
    match result {
        Ok(mut response) => {
            response.headers_mut().insert(
                "x-traffic-e2e-case-id",
                session.case.id.to_string().parse().expect("UUID header"),
            );
            response
        }
        Err(error) => {
            tracing::warn!(%error, case_id = %session.case.id, "interaction dispatch failed");
            session.request_close(EndReason::TransportError);
            simple_response(StatusCode::BAD_GATEWAY, "interaction dispatch failed")
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "transfer the already admitted ordinary HTTP case to response-stream ownership"
)]
pub(super) async fn adopt_response(
    state: AppState,
    case: CaseContext,
    guard: Arc<ActiveCaseGuard>,
    client_addr: Option<String>,
    method: hyper::Method,
    original_uri: Uri,
    api_pattern: String,
    headers: crate::recorder::HeaderMapSnapshot,
    raw_headers: hyper::HeaderMap,
    request_body: Bytes,
    upstream: String,
    started: Instant,
    status: StatusCode,
    response_headers: hyper::HeaderMap,
    body: Incoming,
) -> Response<GatewayBody> {
    let protocol =
        response_protocol(&response_headers).expect("response stream protocol was classified");
    let policy = state.config().http_gateway.interaction_policy(protocol);
    let observation = if method == hyper::Method::GET
        && protocol == Protocol::Sse
        && policy.stream_terminal.is_none()
    {
        Observation::new_sse_subscription(
            policy,
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        )
    } else {
        Observation::new(protocol, policy)
    }
    .expect("validated stream policy");
    let (close, _) = watch::channel(None);
    let session = Arc::new(Session {
        state: state.clone(),
        case,
        observation: Mutex::new(observation),
        started,
        close,
        changed: Notify::new(),
        upstream,
        original_uri: original_uri.clone(),
        method: method.clone(),
        request_headers: raw_headers.clone(),
        response: Mutex::new(None),
        sid: Mutex::new(None),
        active_io: std::sync::atomic::AtomicUsize::new(0),
        transports: Mutex::new(Vec::new()),
        upgraded: std::sync::atomic::AtomicBool::new(false),
        eio_closed: std::sync::atomic::AtomicBool::new(false),
    });
    if !state.config().http_gateway.record_streaming {
        state.invalidate_active_case(session.case.id, crate::recorder::CaseInvalidation::new("streaming_disabled", "response declared a stream after admission; enable http_gateway.record_streaming and record again"));
    }
    let meta = finish::RequestMeta {
        timestamp: Utc::now(),
        method: method.to_string(),
        uri: original_uri.to_string(),
        api_pattern,
        headers,
        raw_headers,
        body: request_body,
        client_addr,
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    let result = stream::forward(response, session.clone()).await;
    finish::spawn(session.clone(), guard, meta);
    match result {
        Ok(mut response) => {
            response.headers_mut().insert(
                "x-traffic-e2e-case-id",
                session.case.id.to_string().parse().expect("UUID header"),
            );
            response
        }
        Err(_) => {
            session.request_close(EndReason::ProtocolError);
            simple_response(StatusCode::BAD_GATEWAY, "failed to observe stream response")
        }
    }
}

fn is_websocket<B>(req: &Request<B>) -> bool {
    req.headers()
        .get("upgrade")
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

async fn dispatch(
    mut req: Request<Incoming>,
    session: SessionRef,
    initial: bool,
) -> Result<Response<GatewayBody>> {
    let upgrade = if is_websocket(&req) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let (parts, body) = req.into_parts();
    let bytes = Limited::new(body, session.state.config().recording.max_body_bytes)
        .collect()
        .await
        .map_err(anyhow::Error::from_boxed)?
        .to_bytes();
    let mut req = Request::from_parts(parts, Full::new(bytes));
    if let Some(upgrade) = upgrade {
        req.extensions_mut()
            .insert(websocket::DownstreamUpgrade(Arc::new(Mutex::new(Some(
                upgrade,
            )))));
    }
    dispatch_full(req, session, initial).await
}

async fn dispatch_full(
    req: Request<Full<Bytes>>,
    session: SessionRef,
    initial: bool,
) -> Result<Response<GatewayBody>> {
    if is_websocket(&req) {
        websocket::dispatch(req, session, initial).await
    } else {
        polling::dispatch(req, session, initial).await
    }
}

async fn passthrough(
    mut req: Request<Incoming>,
    state: &AppState,
    config: &HttpGatewayConfig,
) -> Response<GatewayBody> {
    if config.fallback_mode == crate::HttpGatewayFallbackMode::FixedResponse {
        return transport::build_fixed_response(
            config.fixed_response.as_ref().expect("validated fallback"),
        );
    }
    let upgraded = is_websocket(&req);
    let downstream = upgraded.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let result = async {
        let body = Limited::new(body, state.config().recording.max_body_bytes)
            .collect()
            .await
            .map_err(anyhow::Error::from_boxed)?
            .to_bytes();
        let uri = transport::build_upstream_uri(&config.fallback_upstream, &parts.uri)?;
        let mut request = transport::build_upstream_request(
            &parts.method,
            uri,
            body,
            &parts.headers,
            config.preserve_host,
        )?;
        if upgraded {
            websocket::restore_upgrade(&parts.headers, request.headers_mut());
        }
        let mut response = state.client().request(request).await?;
        if let Some(downstream) =
            downstream.filter(|_| response.status() == StatusCode::SWITCHING_PROTOCOLS)
        {
            let upstream = hyper::upgrade::on(&mut response);
            tokio::spawn(async move {
                if let (Ok(downstream), Ok(upstream)) = tokio::join!(downstream, upstream) {
                    let _ = tokio::io::copy_bidirectional(
                        &mut hyper_util::rt::TokioIo::new(downstream),
                        &mut hyper_util::rt::TokioIo::new(upstream),
                    )
                    .await;
                }
            });
        }
        let (parts, body) = response.into_parts();
        Ok::<_, anyhow::Error>(Response::from_parts(
            parts,
            body.map_err(anyhow::Error::from).boxed_unsync(),
        ))
    }
    .await;
    result
        .unwrap_or_else(|_| simple_response(StatusCode::BAD_GATEWAY, "interaction fallback failed"))
}
