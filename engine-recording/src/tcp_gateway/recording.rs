//! Fake-IP dependency evidence and error persistence.
use super::*;

pub(super) async fn record_proxy_error(
    state: &AppState,
    protocol: &str,
    client_addr: Option<String>,
    target: Option<String>,
    error: String,
) {
    record_event_and_case_dependency(
        state,
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            connection_id: None,
            timestamp: Utc::now(),
            protocol: protocol.to_string(),
            client_addr,
            target,
            error,
        }),
    );
}

pub(super) struct HttpErrorContext {
    pub(super) targets: DependencyTargets,
    pub(super) state: AppState,
    pub(super) id: Uuid,
    pub(super) client_addr: Option<String>,
    pub(super) scheme: String,
    pub(super) method: Method,
    pub(super) original_uri: Uri,
    pub(super) authority: Option<String>,
    pub(super) request_headers: HeaderMapSnapshot,
    pub(super) request_body: Bytes,
    pub(super) started: Instant,
    pub(super) request_started_at: chrono::DateTime<Utc>,
    pub(super) entry: FakeDnsEntry,
    pub(super) fake_addr: SocketAddr,
    pub(super) upstream_addr: Option<SocketAddr>,
    pub(super) err: anyhow::Error,
}

pub(super) async fn record_http_error(ctx: HttpErrorContext) -> Response<GatewayBody> {
    let error = ctx.err.to_string();
    let event = HttpExchangeEvent {
        outcome: crate::DependencyExchangeOutcome::Response,
        id: ctx.id,
        timestamp: Utc::now(),
        request_started_at: ctx.request_started_at,
        client_addr: ctx.client_addr.clone(),
        upstream_addr: ctx.upstream_addr,
        scheme: ctx.scheme.clone(),
        method: ctx.method.to_string(),
        uri: ctx.original_uri.to_string(),
        authority: ctx.authority.clone(),
        request_headers: with_fake_gateway_headers(
            ctx.request_headers,
            &ctx.entry,
            ctx.fake_addr,
            ctx.upstream_addr,
        ),
        request_body: ctx.request_body.into(),
        response_status: None,
        response_headers: None,
        response_body: None,
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: ctx.started.elapsed().as_millis(),
        error: Some(error.clone()),
    };
    ctx.state
        .record_event_for_targets(RecorderEvent::HttpExchange(event), ctx.targets.clone());
    record_proxy_error(
        &ctx.state,
        &ctx.scheme,
        ctx.client_addr,
        ctx.upstream_addr.map(|addr| addr.to_string()),
        error.clone(),
    )
    .await;
    simple_response(StatusCode::BAD_GATEWAY, &error)
}

pub(super) struct TcpConnectionRecord {
    pub(super) id: Uuid,
    pub(super) client_addr: Option<String>,
    pub(super) domain: Option<String>,
    pub(super) fake_addr: SocketAddr,
    pub(super) upstream_addr: Option<SocketAddr>,
    pub(super) client_to_server_bytes: u64,
    pub(super) server_to_client_bytes: u64,
    pub(super) duration_ms: u128,
    pub(super) error: Option<String>,
}

pub(super) async fn record_tcp_connection(
    state: &AppState,
    record: TcpConnectionRecord,
    targets: DependencyTargets,
) {
    state.record_event_for_targets(
        RecorderEvent::TcpGatewayConnection(TcpGatewayConnectionEvent {
            id: record.id,
            timestamp: Utc::now(),
            client_addr: record.client_addr,
            domain: record.domain,
            fake_addr: record.fake_addr.to_string(),
            upstream_addr: record.upstream_addr.map(|addr| addr.to_string()),
            client_to_server_bytes: record.client_to_server_bytes,
            server_to_client_bytes: record.server_to_client_bytes,
            duration_ms: record.duration_ms,
            error: record.error,
        }),
        targets,
    );
}

fn record_event_and_case_dependency(state: &AppState, event: RecorderEvent) {
    state.record_event(event);
}
