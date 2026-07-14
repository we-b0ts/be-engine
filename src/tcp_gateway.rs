use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::warn;
use uuid::Uuid;

use crate::access_policy::AccessDecision;
use crate::dns_mock::{FakeDnsEntry, FakeDnsUpstreamProtocol};
use crate::http::access::classify_method;
use crate::http::rewrite::{self, RewriteInput};
use crate::process_lookup::process_label;
use crate::recorder::{
    HeaderMapSnapshot, HttpExchangeEvent, ProcessInfo, ProxyErrorEvent, RecorderEvent,
    TcpGatewayConnectionEvent, capture_body, redact_headers,
};
use crate::{AppState, ProxyClient};

mod connection;
mod detection;
mod http_transport;
#[cfg(test)]
mod tests;

pub(crate) use connection::run;
use connection::upstream_addr;
use detection::DetectedProtocol;
use http_transport::{
    GatewayBody, build_downstream_response, build_origin_form_uri, build_upstream_request,
    build_upstream_uri, simple_response,
};

struct RawTcpOptions {
    record_connection: bool,
    sniff_server_first_protocols: bool,
    detected_protocol: Option<DetectedProtocol>,
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
    let operation_class = classify_method(&method);
    if state.access_decision(operation_class) == AccessDecision::Reject {
        state
            .record_readonly_rejection(
                "fake_ip_http",
                operation_class,
                method.to_string(),
                client_addr,
                client_process,
                Some(format!("{}:{}", entry.domain, fake_addr.port())),
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
        entry.upstream_authority.as_deref(),
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
            let mut response_headers = upstream_response.headers().clone();
            let mut body_bytes = match upstream_response.into_body().collect().await {
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
                }
                Ok(None) => {}
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
            }
            let response_headers_for_record =
                redact_headers(&response_headers, &state.config().recording.redact_headers);

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
    let operation_class = classify_method(&method);
    if state.access_decision(operation_class) == AccessDecision::Reject {
        state
            .record_readonly_rejection(
                "fake_ip_https",
                operation_class,
                method.to_string(),
                client_addr.clone(),
                client_process.clone(),
                Some(fallback_authority.clone()),
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

    let plain_http_upstream = entry.upstream_protocol == Some(FakeDnsUpstreamProtocol::Http);
    let outbound_uri = match if plain_http_upstream {
        build_upstream_uri(upstream_addr, &original_uri)
    } else {
        build_origin_form_uri(&original_uri)
    } {
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
        entry.upstream_authority.as_deref(),
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

    let upstream_response = if plain_http_upstream {
        send_upstream(state.client(), outbound)
            .await
            .map_err(anyhow::Error::from)
    } else {
        send_https_upstream(&state, upstream_addr, &entry.domain, outbound).await
    };
    match upstream_response {
        Ok(upstream_response) => {
            let status = upstream_response.status();
            let mut response_headers = upstream_response.headers().clone();
            let mut body_bytes = match upstream_response.into_body().collect().await {
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
                }
                Ok(None) => {}
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
            }
            let response_headers_for_record =
                redact_headers(&response_headers, &state.config().recording.redact_headers);

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
                err: anyhow!("fake-IP HTTPS client upstream request failed: {err}"),
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
