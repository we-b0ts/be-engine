use std::convert::Infallible;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, HOST};
use hyper::http::uri::{Authority, PathAndQuery, Scheme};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};
use uuid::Uuid;

use crate::dns_mock::{FakeDnsEntry, domain_matches};
use crate::mysql_proxy::{MysqlConnectionContext, handle_connected_mysql};
use crate::process_lookup::{lookup_tcp_process, process_label};
use crate::recorder::{
    HeaderMapSnapshot, HttpExchangeEvent, ProcessInfo, ProxyErrorEvent, RecorderEvent,
    TcpGatewayConnectionEvent, capture_body, redact_headers,
};
use crate::{AppState, ProxyClient};

const SO_ORIGINAL_DST: libc::c_int = 80;
const PROTOCOL_PEEK_TIMEOUT: Duration = Duration::from_millis(100);

type GatewayBody = BoxBody<Bytes, Infallible>;

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config().tcp_gateway.clone();
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind TCP gateway {}", config.listen))?;
    info!(listen = %config.listen, "TCP fake-IP gateway listening");

    loop {
        let (client, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept TCP gateway client")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(client, peer_addr, state).await {
                warn!(error = %format!("{err:#}"), "TCP gateway connection failed");
            }
        });
    }
}

async fn handle_connection(
    client: TcpStream,
    peer_addr: SocketAddr,
    state: AppState,
) -> Result<()> {
    let fake_addr = original_dst(&client).or_else(|err| {
        warn!(error = %err, "SO_ORIGINAL_DST unavailable; falling back to local_addr");
        client.local_addr().context("failed to read local_addr")
    })?;
    let client_addr = Some(peer_addr.to_string());
    let mut process_remote_candidates = vec![fake_addr];
    if let Ok(gateway_addr) = client.local_addr() {
        process_remote_candidates.push(gateway_addr);
    }
    let client_process = lookup_tcp_process(peer_addr, &process_remote_candidates);

    let IpAddr::V4(fake_ip) = fake_addr.ip() else {
        return Err(anyhow!("TCP gateway only supports IPv4 fake IPs"));
    };
    let Some(entry) = state.dns_registry().get_by_fake_ip(fake_ip).await else {
        let error = format!(
            "no DNS mock mapping for fake IP {fake_ip}; likely stale client DNS cache, recorder restart without persisted mapping, or traffic not produced by this DNS mock"
        );
        record_proxy_error(
            &state,
            "tcp_gateway",
            client_addr.clone(),
            client_process.clone(),
            Some(fake_addr.to_string()),
            error.clone(),
        )
        .await;
        return Err(anyhow!("{error}"));
    };

    if domain_matches(&entry.domain, &state.config().dns_mock.bypass_domains) {
        return proxy_raw_tcp(
            client,
            fake_addr,
            entry,
            client_addr,
            client_process,
            state,
            RawTcpOptions {
                record_connection: false,
                sniff_server_first_protocols: false,
            },
        )
        .await;
    }

    let config = state.config().tcp_gateway.clone();
    let protocol_prefix = if config.record_http {
        peek_protocol_prefix(&client).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    if config.record_http && looks_like_http_prefix(&protocol_prefix) {
        return serve_http_connection(client, fake_addr, entry, client_addr, client_process, state)
            .await;
    }
    if config.record_http
        && config.mitm_https
        && should_mitm_https_prefix(fake_addr.port(), &config.https_ports, &protocol_prefix)
    {
        return serve_https_mitm_connection(
            client,
            fake_addr,
            entry,
            client_addr,
            client_process,
            state,
        )
        .await;
    }

    proxy_raw_tcp(
        client,
        fake_addr,
        entry,
        client_addr,
        client_process,
        state,
        RawTcpOptions {
            record_connection: true,
            sniff_server_first_protocols: protocol_prefix.is_empty(),
        },
    )
    .await
}

struct RawTcpOptions {
    record_connection: bool,
    sniff_server_first_protocols: bool,
}

async fn proxy_raw_tcp(
    mut client: TcpStream,
    fake_addr: SocketAddr,
    entry: FakeDnsEntry,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    state: AppState,
    options: RawTcpOptions,
) -> Result<()> {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let upstream_addr = upstream_addr(&entry, fake_addr.port())?;
    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(upstream) => upstream,
        Err(err) => {
            if options.record_connection {
                record_tcp_connection(
                    &state,
                    TcpConnectionRecord {
                        id,
                        client_addr: client_addr.clone(),
                        client_process: client_process.clone(),
                        domain: Some(entry.domain.clone()),
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        client_to_server_bytes: 0,
                        server_to_client_bytes: 0,
                        duration_ms: started.elapsed().as_millis(),
                        error: Some(err.to_string()),
                    },
                )
                .await;
            }
            return Err(err).with_context(|| format!("failed to connect upstream {upstream_addr}"));
        }
    };

    if options.sniff_server_first_protocols
        && upstream_looks_like_mysql(&upstream).await.unwrap_or(false)
    {
        let context = MysqlConnectionContext {
            route_name: Some(format!("fake-ip:{}", entry.domain)),
            listen_addr: state.config().tcp_gateway.listen.to_string(),
            client_addr,
            client_process,
            target_host: Some(entry.domain.clone()),
            target_port: Some(fake_addr.port()),
            target_addr: Some(format_authority(&entry.domain, fake_addr.port(), 3306)),
            upstream_addr: upstream_addr.to_string(),
        };
        return handle_connected_mysql(client, upstream, state, context).await;
    }

    let (client_to_server, server_to_client) = io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("failed to proxy TCP gateway stream")?;
    if options.record_connection {
        record_tcp_connection(
            &state,
            TcpConnectionRecord {
                id,
                client_addr,
                client_process,
                domain: Some(entry.domain),
                fake_addr,
                upstream_addr: Some(upstream_addr),
                client_to_server_bytes: client_to_server,
                server_to_client_bytes: server_to_client,
                duration_ms: started.elapsed().as_millis(),
                error: None,
            },
        )
        .await;
    }
    Ok(())
}

async fn serve_http_connection(
    client: TcpStream,
    fake_addr: SocketAddr,
    entry: FakeDnsEntry,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    state: AppState,
) -> Result<()> {
    let upstream_addr = upstream_addr(&entry, fake_addr.port())?;
    let io = TokioIo::new(client);
    let service = service_fn(move |req| {
        let state = state.clone();
        let entry = entry.clone();
        let client_addr = client_addr.clone();
        let client_process = client_process.clone();
        async move {
            Ok::<_, Infallible>(
                handle_http_request(
                    req,
                    state,
                    entry,
                    fake_addr,
                    upstream_addr,
                    client_addr,
                    client_process,
                )
                .await,
            )
        }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .await
        .context("failed to serve fake-IP HTTP gateway connection")?;
    Ok(())
}

async fn serve_https_mitm_connection(
    client: TcpStream,
    fake_addr: SocketAddr,
    entry: FakeDnsEntry,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    state: AppState,
) -> Result<()> {
    let upstream_addr = upstream_addr(&entry, fake_addr.port())?;
    let authority = format_authority(&entry.domain, fake_addr.port(), 443);
    let server_config = state
        .ca()
        .server_config_for_host(&entry.domain)
        .with_context(|| format!("failed to create MITM certificate for {}", entry.domain))?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls = match acceptor.accept(client).await {
        Ok(tls) => tls,
        Err(err) => {
            let error = err.to_string();
            let client_process_label = client_process.as_ref().map(process_label);
            warn!(
                protocol = "fake_ip_https",
                client_addr = client_addr.as_deref(),
                client_process = client_process_label.as_deref(),
                target = %authority,
                fake_addr = %fake_addr,
                upstream_addr = %upstream_addr,
                error = %error,
                "fake-IP HTTPS client TLS handshake failed"
            );
            record_proxy_error(
                &state,
                "fake_ip_https",
                client_addr.clone(),
                client_process,
                Some(authority),
                error,
            )
            .await;
            return Ok(());
        }
    };

    let io = TokioIo::new(tls);
    let service = service_fn(move |req| {
        let state = state.clone();
        let entry = entry.clone();
        let client_addr = client_addr.clone();
        let client_process = client_process.clone();
        let authority = authority.clone();
        async move {
            Ok::<_, Infallible>(
                handle_https_request(
                    req,
                    state,
                    entry,
                    fake_addr,
                    upstream_addr,
                    HttpsRequestContext {
                        client_addr,
                        client_process,
                        fallback_authority: authority,
                    },
                )
                .await,
            )
        }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .await
        .context("failed to serve fake-IP HTTPS MITM connection")?;
    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    state: AppState,
    entry: FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: SocketAddr,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
) -> Response<GatewayBody> {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let method = req.method().clone();
    let original_uri = req.uri().clone();
    let request_headers = req.headers().clone();
    let request_headers_for_record =
        redact_headers(&request_headers, &state.config().recording.redact_headers);
    let authority = request_authority(&original_uri, &request_headers)
        .or_else(|| Some(format!("{}:{}", entry.domain, fake_addr.port())));

    let request_body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body: Bytes::new(),
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err: anyhow!("failed to read fake-IP HTTP request body: {err}"),
            })
            .await;
        }
    };

    let outbound_uri = match build_upstream_uri(upstream_addr, &original_uri) {
        Ok(uri) => uri,
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
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
        &entry.domain,
        fake_addr.port(),
    ) {
        Ok(req) => req,
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
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
                    return record_http_error(HttpErrorContext {
                        state,
                        id,
                        client_addr,
                        client_process,
                        scheme: "fake_ip_http".to_string(),
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
                        entry,
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        err: anyhow!("failed to read fake-IP HTTP upstream response body: {err}"),
                    })
                    .await;
                }
            };

            let event = HttpExchangeEvent {
                id,
                timestamp: Utc::now(),
                client_addr,
                client_process,
                scheme: "fake_ip_http".to_string(),
                method: method.to_string(),
                uri: original_uri.to_string(),
                authority,
                request_headers: with_fake_gateway_headers(
                    request_headers_for_record,
                    &entry,
                    fake_addr,
                    Some(upstream_addr),
                ),
                request_body: capture_body(&request_body, state.config().recording.max_body_bytes),
                response_status: Some(status.as_u16()),
                response_headers: Some(response_headers_for_record),
                response_body: Some(capture_body(
                    &body_bytes,
                    state.config().recording.max_body_bytes,
                )),
                duration_ms: started.elapsed().as_millis(),
                error: None,
            };
            record_event_and_case_dependency(
                &state,
                RecorderEvent::HttpExchange(event),
                "failed to record fake-IP HTTP exchange",
            )
            .await;

            build_downstream_response(status, &response_headers, body_bytes)
        }
        Err(err) => {
            record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err: anyhow!("fake-IP HTTP upstream request failed: {err}"),
            })
            .await
        }
    }
}

struct HttpsRequestContext {
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    fallback_authority: String,
}

async fn handle_https_request(
    req: Request<Incoming>,
    state: AppState,
    entry: FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: SocketAddr,
    client: HttpsRequestContext,
) -> Response<GatewayBody> {
    let HttpsRequestContext {
        client_addr,
        client_process,
        fallback_authority,
    } = client;
    let id = Uuid::new_v4();
    let started = Instant::now();
    let method = req.method().clone();
    let original_uri = req.uri().clone();
    let request_headers = req.headers().clone();
    let request_headers_for_record =
        redact_headers(&request_headers, &state.config().recording.redact_headers);
    let authority =
        request_authority(&original_uri, &request_headers).or(Some(fallback_authority.clone()));

    let request_body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body: Bytes::new(),
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err: anyhow!("failed to read fake-IP HTTPS request body: {err}"),
            })
            .await;
        }
    };

    let outbound_uri = match build_origin_form_uri(&original_uri) {
        Ok(uri) => uri,
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
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
        &entry.domain,
        fake_addr.port(),
    ) {
        Ok(req) => req,
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err,
            })
            .await;
        }
    };

    match send_https_upstream(&state, upstream_addr, &entry.domain, outbound).await {
        Ok(upstream_response) => {
            let status = upstream_response.status();
            let response_headers = upstream_response.headers().clone();
            let response_headers_for_record =
                redact_headers(&response_headers, &state.config().recording.redact_headers);
            let body_bytes = match upstream_response.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => {
                    return record_http_error(HttpErrorContext {
                        state,
                        id,
                        client_addr,
                        client_process,
                        scheme: "fake_ip_https".to_string(),
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
                        entry,
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        err: anyhow!("failed to read fake-IP HTTPS upstream response body: {err}"),
                    })
                    .await;
                }
            };

            let event = HttpExchangeEvent {
                id,
                timestamp: Utc::now(),
                client_addr,
                client_process,
                scheme: "fake_ip_https".to_string(),
                method: method.to_string(),
                uri: original_uri.to_string(),
                authority,
                request_headers: with_fake_gateway_headers(
                    request_headers_for_record,
                    &entry,
                    fake_addr,
                    Some(upstream_addr),
                ),
                request_body: capture_body(&request_body, state.config().recording.max_body_bytes),
                response_status: Some(status.as_u16()),
                response_headers: Some(response_headers_for_record),
                response_body: Some(capture_body(
                    &body_bytes,
                    state.config().recording.max_body_bytes,
                )),
                duration_ms: started.elapsed().as_millis(),
                error: None,
            };
            record_event_and_case_dependency(
                &state,
                RecorderEvent::HttpExchange(event),
                "failed to record fake-IP HTTPS exchange",
            )
            .await;

            build_downstream_response(status, &response_headers, body_bytes)
        }
        Err(err) => {
            record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                client_process,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err: anyhow!("fake-IP HTTPS upstream request failed: {err}"),
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

async fn send_https_upstream(
    state: &AppState,
    upstream_addr: SocketAddr,
    server_name: &str,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>> {
    let stream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("failed to connect HTTPS upstream {upstream_addr}"))?;
    let connector = TlsConnector::from(state.upstream_tls_config());
    let server_name = ServerName::try_from(server_name.to_string())
        .with_context(|| format!("invalid HTTPS upstream server name {server_name}"))?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .with_context(|| format!("failed TLS handshake with HTTPS upstream {upstream_addr}"))?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls))
        .await
        .context("failed HTTP/1.1 handshake with HTTPS upstream")?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!(error = %err, "fake-IP HTTPS upstream connection ended with error");
        }
    });
    sender
        .send_request(request)
        .await
        .context("failed to send fake-IP HTTPS upstream request")
}

async fn record_proxy_error(
    state: &AppState,
    protocol: &str,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    target: Option<String>,
    error: String,
) {
    record_event_and_case_dependency(
        state,
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: protocol.to_string(),
            client_addr,
            client_process,
            target,
            error,
        }),
        "failed to record proxy error",
    )
    .await;
}

struct HttpErrorContext {
    state: AppState,
    id: Uuid,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    scheme: String,
    method: Method,
    original_uri: Uri,
    authority: Option<String>,
    request_headers: HeaderMapSnapshot,
    request_body: Bytes,
    started: Instant,
    entry: FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: Option<SocketAddr>,
    err: anyhow::Error,
}

async fn record_http_error(ctx: HttpErrorContext) -> Response<GatewayBody> {
    let error = ctx.err.to_string();
    let event = HttpExchangeEvent {
        id: ctx.id,
        timestamp: Utc::now(),
        client_addr: ctx.client_addr.clone(),
        client_process: ctx.client_process.clone(),
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
    record_event_and_case_dependency(
        &ctx.state,
        RecorderEvent::HttpExchange(event),
        "failed to record failed fake-IP HTTP exchange",
    )
    .await;
    record_proxy_error(
        &ctx.state,
        &ctx.scheme,
        ctx.client_addr,
        ctx.client_process,
        ctx.upstream_addr.map(|addr| addr.to_string()),
        error.clone(),
    )
    .await;
    simple_response(StatusCode::BAD_GATEWAY, &error)
}

struct TcpConnectionRecord {
    id: Uuid,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    domain: Option<String>,
    fake_addr: SocketAddr,
    upstream_addr: Option<SocketAddr>,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    duration_ms: u128,
    error: Option<String>,
}

async fn record_tcp_connection(state: &AppState, record: TcpConnectionRecord) {
    record_event_and_case_dependency(
        state,
        RecorderEvent::TcpGatewayConnection(TcpGatewayConnectionEvent {
            id: record.id,
            timestamp: Utc::now(),
            client_addr: record.client_addr,
            client_process: record.client_process,
            domain: record.domain,
            fake_addr: record.fake_addr.to_string(),
            upstream_addr: record.upstream_addr.map(|addr| addr.to_string()),
            client_to_server_bytes: record.client_to_server_bytes,
            server_to_client_bytes: record.server_to_client_bytes,
            duration_ms: record.duration_ms,
            error: record.error,
        }),
        "failed to record TCP gateway connection",
    )
    .await;
}

async fn record_event_and_case_dependency(
    state: &AppState,
    event: RecorderEvent,
    warning: &'static str,
) {
    if let Err(err) = state.recorder().record(event.clone()).await {
        warn!(error = %err, "{}", warning);
    }
    state.record_dependency_if_relevant(&event).await;
}

fn build_upstream_uri(upstream_addr: SocketAddr, original_uri: &Uri) -> Result<Uri> {
    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let mut parts = hyper::http::uri::Parts::default();
    parts.scheme = Some(Scheme::HTTP);
    parts.authority = Some(Authority::try_from(upstream_addr.to_string())?);
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct fake-IP HTTP upstream URI")
}

fn build_origin_form_uri(original_uri: &Uri) -> Result<Uri> {
    let path_and_query = original_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let mut parts = hyper::http::uri::Parts::default();
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct fake-IP HTTPS upstream URI")
}

fn build_upstream_request(
    method: &Method,
    uri: Uri,
    body: Bytes,
    source_headers: &HeaderMap,
    domain: &str,
    original_port: u16,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder().method(method).uri(uri);
    let headers = builder.headers_mut().expect("request builder headers");
    for (name, value) in source_headers {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        headers.append(name, value.clone());
    }
    if !headers.contains_key(HOST) {
        let host = if original_port == 80 {
            domain.to_string()
        } else {
            format!("{domain}:{original_port}")
        };
        headers.insert(HOST, host.parse()?);
    }
    builder
        .body(Full::new(body))
        .context("failed to build fake-IP HTTP upstream request")
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

fn format_authority(domain: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        domain.to_string()
    } else {
        format!("{domain}:{port}")
    }
}

fn with_fake_gateway_headers(
    mut headers: HeaderMapSnapshot,
    entry: &FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: Option<SocketAddr>,
) -> HeaderMapSnapshot {
    headers
        .entry("x-recorder-fake-ip".to_string())
        .or_default()
        .push(fake_addr.to_string());
    headers
        .entry("x-recorder-original-domain".to_string())
        .or_default()
        .push(entry.domain.clone());
    if let Some(upstream_addr) = upstream_addr {
        headers
            .entry("x-recorder-upstream-addr".to_string())
            .or_default()
            .push(upstream_addr.to_string());
    }
    headers
}

fn upstream_addr(entry: &FakeDnsEntry, port: u16) -> Result<SocketAddr> {
    let ip = entry
        .real_ips
        .first()
        .copied()
        .ok_or_else(|| anyhow!("DNS mock entry has no real IPs for {}", entry.domain))?;
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

async fn peek_protocol_prefix(stream: &TcpStream) -> Result<Vec<u8>> {
    let mut buf = [0_u8; 8];
    let n = match timeout(PROTOCOL_PEEK_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Ok(Vec::new()),
    };
    Ok(buf[..n.min(buf.len())].to_vec())
}

fn looks_like_http_prefix(bytes: &[u8]) -> bool {
    [
        b"GET ".as_slice(),
        b"POST ".as_slice(),
        b"PUT ".as_slice(),
        b"PATCH ".as_slice(),
        b"DELETE ".as_slice(),
        b"HEAD ".as_slice(),
        b"OPTIONS ".as_slice(),
    ]
    .iter()
    .any(|prefix| bytes.starts_with(prefix))
}

fn should_mitm_https_prefix(port: u16, https_ports: &[u16], bytes: &[u8]) -> bool {
    if !https_ports.is_empty() && !https_ports.contains(&port) {
        return false;
    }
    looks_like_tls_prefix(bytes)
}

async fn upstream_looks_like_mysql(stream: &TcpStream) -> Result<bool> {
    let mut buf = [0_u8; 5];
    let n = match timeout(PROTOCOL_PEEK_TIMEOUT, stream.peek(&mut buf)).await {
        Ok(result) => result?,
        Err(_) => return Ok(false),
    };
    Ok(looks_like_mysql_handshake_prefix(&buf[..n]))
}

fn looks_like_tls_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x04
}

fn looks_like_mysql_handshake_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[3] == 0 && bytes[4] == 0x0a
}

fn original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len as *mut _,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt SO_ORIGINAL_DST failed");
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
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
    use crate::dns_mock::FakeDnsEntry;
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn builds_http_upstream_uri_with_original_path() {
        let uri = build_upstream_uri(
            "127.0.0.1:8080".parse().unwrap(),
            &"/hello?a=1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:8080/hello?a=1");
    }

    #[test]
    fn resolves_upstream_from_dns_entry_and_original_port() {
        let entry = FakeDnsEntry {
            domain: "api.example.com".to_string(),
            fake_ip: Ipv4Addr::new(198, 18, 0, 1),
            real_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        assert_eq!(
            upstream_addr(&entry, 8080).unwrap(),
            "10.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn detects_tls_client_hello_prefix() {
        assert!(looks_like_tls_prefix(&[0x16, 0x03, 0x03]));
        assert!(!looks_like_tls_prefix(b"GET /"));
    }

    #[tokio::test]
    async fn mitms_fake_ip_https_and_records_exchange() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let temp = tempdir().unwrap();
        let mut config = crate::AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = crate::AppState::new(config).await.unwrap();

        let upstream_config = state.ca().server_config_for_host("example.test").unwrap();
        let upstream_addr = spawn_https_upstream(upstream_config).await;
        let entry = FakeDnsEntry {
            domain: "example.test".to_string(),
            fake_ip: Ipv4Addr::new(198, 18, 0, 1),
            real_ips: vec![Ipv4Addr::new(127, 0, 0, 1)],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        let fake_addr = SocketAddr::new(IpAddr::V4(entry.fake_ip), upstream_addr.port());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = listener.local_addr().unwrap();
        let state_for_gateway = state.clone();
        let gateway = tokio::spawn(async move {
            let (client, peer) = listener.accept().await.unwrap();
            serve_https_mitm_connection(
                client,
                fake_addr,
                entry,
                Some(peer.to_string()),
                None,
                state_for_gateway,
            )
            .await
            .unwrap();
        });

        let stream = TcpStream::connect(gateway_addr).await.unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(state.ca().ca_cert_der()).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = TlsConnector::from(client_config);
        let server_name = ServerName::try_from("example.test".to_string()).unwrap();
        let tls = connector.connect(server_name, stream).await.unwrap();
        let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = Request::builder()
            .method(Method::GET)
            .uri("/secure")
            .header(HOST, "example.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"secure");
        drop(sender);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        gateway.abort();

        let jsonl = tokio::fs::read_to_string(temp.path().join("recordings/traffic.jsonl"))
            .await
            .unwrap();
        assert!(jsonl.contains(r#""event_type":"http_exchange""#));
        assert!(jsonl.contains(r#""scheme":"fake_ip_https""#));
        assert!(jsonl.contains("/secure"));
    }

    async fn spawn_https_upstream(config: Arc<rustls::ServerConfig>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(config);
            let tls = acceptor.accept(stream).await.unwrap();
            let service = service_fn(|_req| async {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONNECTION, "close")
                        .body(Full::new(Bytes::from_static(b"secure")))
                        .unwrap(),
                )
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .unwrap();
        });
        addr
    }
}
