use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::warn;
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::AccessDecision;
use crate::active_case::DependencyTargets;
use crate::dns_mock::{FakeDnsEntry, FakeDnsUpstreamProtocol};
use crate::http::access::classify_method;
use crate::http::rewrite::{self, RewriteInput};
use crate::http::termination::{ClientTermination, ObservedClientIo};
use crate::recorder::connections::DependencyIo;
use crate::recorder::http::dependency::PendingHttpCapture;
use crate::recorder::http::stream;
use crate::recorder::{
    HeaderMapSnapshot, HttpExchangeEvent, ProxyErrorEvent, RecorderEvent,
    TcpGatewayConnectionEvent, capture_body, redact_headers,
};

mod connection;
mod detection;
mod http_transport;
mod recording;
use recording::{
    HttpErrorContext, TcpConnectionRecord, record_http_error, record_proxy_error,
    record_tcp_connection,
};
#[cfg(test)]
mod tests;
#[cfg(test)]
mod timeout_tests;

use connection::routed_upstream_addr as upstream_addr;
pub(crate) use connection::run;
use detection::DetectedProtocol;
pub(crate) use detection::{
    DetectedProtocol as DetectedClientProtocol, Detection as ClientProtocolDetection,
    detect_client_protocol,
};
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
    state: AppState,
) -> Result<()> {
    let upstream_addr = upstream_addr(&state, &entry, fake_addr.port())?;
    let termination = ClientTermination::with_control(&client)?;
    let client = DependencyIo::new_observed(
        client,
        state.dependency_connections(),
        "http",
        termination.connection_observation(),
    )?;
    let _registration = client.registration();
    let owner = termination.clone();
    let io = TokioIo::new(ObservedClientIo::new(client, termination.clone()));
    let service = service_fn(move |req| {
        let state = state.clone();
        let entry = entry.clone();
        let client_addr = client_addr.clone();
        let termination = termination.clone();
        async move {
            Ok::<_, Infallible>(
                handle_http_request(
                    req,
                    state,
                    entry,
                    fake_addr,
                    upstream_addr,
                    client_addr,
                    termination,
                )
                .await,
            )
        }
    });

    let result = owner
        .serve(traffic_protocol_http::HttpProvider::connection(
            io.into_inner(),
            service,
            true,
        ))
        .await;
    if owner.server_write_half_closed() {
        owner.retain_read_half().await?;
        Ok(())
    } else {
        result.context("failed to serve fake-IP HTTP gateway connection")
    }
}

async fn serve_https_mitm_connection(
    client: TcpStream,
    fake_addr: SocketAddr,
    entry: FakeDnsEntry,
    client_addr: Option<String>,
    state: AppState,
) -> Result<()> {
    let upstream_addr = upstream_addr(&state, &entry, fake_addr.port())?;
    let authority = format_authority(&entry.domain, fake_addr.port(), 443);
    let server_config = state
        .ca()
        .server_config_for_host(&entry.domain)
        .with_context(|| format!("failed to create MITM certificate for {}", entry.domain))?;
    let acceptor = TlsAcceptor::from(server_config);
    let termination = ClientTermination::with_control(&client)?;
    let client = DependencyIo::new_observed(
        client,
        state.dependency_connections(),
        "https",
        termination.connection_observation(),
    )?;
    let _registration = client.registration();
    let owner = termination.clone();
    let client = ObservedClientIo::transport(client, termination.clone());
    let tls = match acceptor.accept(client).await {
        Ok(tls) => tls,
        Err(err) => {
            let error = err.to_string();
            warn!(
                protocol = "fake_ip_https",
                client_addr = client_addr.as_deref(),
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
                Some(authority),
                error,
            )
            .await;
            return Ok(());
        }
    };

    let io = TokioIo::new(ObservedClientIo::new(tls, termination.clone()));
    let service = service_fn(move |req| {
        let state = state.clone();
        let entry = entry.clone();
        let client_addr = client_addr.clone();
        let authority = authority.clone();
        let termination = termination.clone();
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
                        fallback_authority: authority,
                        termination,
                    },
                )
                .await,
            )
        }
    });

    let result = owner
        .serve(traffic_protocol_http::HttpProvider::connection(
            io.into_inner(),
            service,
            true,
        ))
        .await;
    if owner.server_write_half_closed() {
        owner.retain_read_half().await?;
        Ok(())
    } else {
        result.context("failed to serve fake-IP HTTPS MITM connection")
    }
}

async fn handle_http_request(
    req: Request<Incoming>,
    state: AppState,
    entry: FakeDnsEntry,
    fake_addr: SocketAddr,
    upstream_addr: SocketAddr,
    client_addr: Option<String>,
    termination: ClientTermination,
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
                "fake_ip_http",
                operation_class,
                method.to_string(),
                client_addr,
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
    let authority = request_authority(&original_uri, &request_headers)
        .or_else(|| Some(format!("{}:{}", entry.domain, fake_addr.port())));
    let targets =
        state.capture_http_dependency_request(&method, &original_uri, authority.as_deref());

    let request_body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return record_http_error(HttpErrorContext {
                targets: targets.clone(),
                state,
                id,
                client_addr,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body: Bytes::new(),
                started,
                request_started_at,
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
                targets: targets.clone(),
                state,
                id,
                client_addr,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                request_started_at,
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
                targets: targets.clone(),
                state,
                id,
                client_addr,
                scheme: "fake_ip_http".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                request_started_at,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err,
            })
            .await;
        }
    };

    let capture_event = HttpExchangeEvent {
        outcome: crate::DependencyExchangeOutcome::Response,
        id,
        timestamp: Utc::now(),
        request_started_at,
        client_addr: client_addr.clone(),
        scheme: "fake_ip_http".to_string(),
        method: method.to_string(),
        uri: original_uri.to_string(),
        authority: authority.clone(),
        request_headers: with_fake_gateway_headers(
            request_headers_for_record.clone(),
            &entry,
            fake_addr,
            Some(upstream_addr),
        ),
        request_body: capture_body(&request_body, state.config().recording.max_body_bytes),
        response_status: None,
        response_headers: None,
        response_body: None,
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 0,
        error: None,
    };
    let pending = PendingHttpCapture::new(
        state.clone(),
        targets.clone(),
        capture_event.clone(),
        started,
        termination.clone(),
    );
    let capture_context = pending.context();
    pending
        .run(async {
            match crate::http::client::send_observed(
                state.recording_http_client(&entry.domain),
                outbound,
                started,
            )
            .await
            {
                Ok(upstream_response) => {
                    if stream::is_stream(upstream_response.headers()) {
                        return stream::response(
                            upstream_response,
                            stream::CaptureContext {
                                state,
                                targets: targets.clone(),
                                event: capture_event,
                                started,
                                termination,
                            },
                        );
                    }
                    let status = upstream_response.status();
                    let mut response_headers = upstream_response.headers().clone();
                    let mut body_bytes = match capture_context
                        .collect_response_body(upstream_response.into_body())
                        .await
                    {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            return record_http_error(HttpErrorContext {
                                targets: targets.clone(),
                                state,
                                id,
                                client_addr,
                                scheme: "fake_ip_http".to_string(),
                                method,
                                original_uri,
                                authority,
                                request_headers: request_headers_for_record,
                                request_body,
                                started,
                                request_started_at,
                                entry,
                                fake_addr,
                                upstream_addr: Some(upstream_addr),
                                err: anyhow!(
                                    "failed to read fake-IP HTTP upstream response body: {err}"
                                ),
                            })
                            .await;
                        }
                    };
                    let mut discovered_tcp_targets = Vec::new();
                    match rewrite::apply(
                        state.response_rewrites(),
                        state.dns_registry(),
                        state.kubectl_proxy_manager(),
                        state.ca().ca_cert_pem_ref(),
                        state.config().recording.decoded_body_limit(),
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
                            targets.transformed(rewritten.transformation);
                            response_headers = rewritten.headers;
                            body_bytes = rewritten.body;
                            discovered_tcp_targets = rewritten.discovered_tcp_targets;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            return record_http_error(HttpErrorContext {
                                targets: targets.clone(),
                                state,
                                id,
                                client_addr,
                                scheme: "fake_ip_http".to_string(),
                                method,
                                original_uri,
                                authority,
                                request_headers: request_headers_for_record,
                                request_body,
                                started,
                                request_started_at,
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
                        outcome: crate::DependencyExchangeOutcome::Response,
                        id,
                        timestamp: Utc::now(),
                        request_started_at,
                        client_addr,
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
                        request_body: capture_body(
                            &request_body,
                            state.config().recording.max_body_bytes,
                        ),
                        response_status: Some(status.as_u16()),
                        response_headers: Some(response_headers_for_record),
                        response_body: Some(capture_body(
                            &body_bytes,
                            state.config().recording.max_body_bytes,
                        )),
                        response_stream: None,
                        discovered_tcp_targets,
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                    };
                    state.record_event_for_targets(
                        RecorderEvent::HttpExchange(event),
                        targets.clone(),
                    );

                    build_downstream_response(status, &response_headers, body_bytes)
                }
                Err(err) => {
                    if let Some(observed) = err.termination
                        && capture_context.forward_server_termination(observed)
                    {
                        return crate::recorder::http::dependency::closed_response();
                    }
                    record_http_error(HttpErrorContext {
                        targets: targets.clone(),
                        state,
                        id,
                        client_addr,
                        scheme: "fake_ip_http".to_string(),
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
                        request_started_at,
                        entry,
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        err: anyhow!("fake-IP HTTP upstream request failed: {err}"),
                    })
                    .await
                }
            }
        })
        .await
}

struct HttpsRequestContext {
    client_addr: Option<String>,
    fallback_authority: String,
    termination: ClientTermination,
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
        fallback_authority,
        termination,
    } = client;
    let id = Uuid::new_v4();
    let started = Instant::now();
    let request_started_at = Utc::now();
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
        match state.recorder().capture_request_headers(&request_headers) {
            Ok(headers) => headers,
            Err(error) => {
                warn!(error = %error, "failed to protect recorded HTTPS request headers");
                return simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to protect recorded request headers",
                );
            }
        };
    let authority =
        request_authority(&original_uri, &request_headers).or(Some(fallback_authority.clone()));
    let targets =
        state.capture_http_dependency_request(&method, &original_uri, authority.as_deref());

    let request_body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return record_http_error(HttpErrorContext {
                targets: targets.clone(),
                state,
                id,
                client_addr,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body: Bytes::new(),
                started,
                request_started_at,
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
                targets: targets.clone(),
                state,
                id,
                client_addr,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                request_started_at,
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
                targets: targets.clone(),
                state,
                id,
                client_addr,
                scheme: "fake_ip_https".to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                request_started_at,
                entry,
                fake_addr,
                upstream_addr: Some(upstream_addr),
                err,
            })
            .await;
        }
    };

    let capture_event = HttpExchangeEvent {
        outcome: crate::DependencyExchangeOutcome::Response,
        id,
        timestamp: Utc::now(),
        request_started_at,
        client_addr: client_addr.clone(),
        scheme: "fake_ip_https".to_string(),
        method: method.to_string(),
        uri: original_uri.to_string(),
        authority: authority.clone(),
        request_headers: with_fake_gateway_headers(
            request_headers_for_record.clone(),
            &entry,
            fake_addr,
            Some(upstream_addr),
        ),
        request_body: capture_body(&request_body, state.config().recording.max_body_bytes),
        response_status: None,
        response_headers: None,
        response_body: None,
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 0,
        error: None,
    };
    let pending = PendingHttpCapture::new(
        state.clone(),
        targets.clone(),
        capture_event.clone(),
        started,
        termination.clone(),
    );
    let capture_context = pending.context();
    pending
        .run(async {
            let upstream_response = if plain_http_upstream {
                crate::http::client::send_observed(state.client(), outbound, started).await
            } else {
                let server_name = entry
                    .upstream_authority
                    .as_deref()
                    .and_then(|authority| authority.split(':').next())
                    .unwrap_or(&entry.domain);
                crate::http::client::send_https_observed(
                    state.upstream_tls_config(),
                    upstream_addr,
                    server_name,
                    outbound,
                    started,
                )
                .await
            };
            match upstream_response {
                Ok(upstream_response) => {
                    if stream::is_stream(upstream_response.headers()) {
                        return stream::response(
                            upstream_response,
                            stream::CaptureContext {
                                state,
                                targets: targets.clone(),
                                event: capture_event,
                                started,
                                termination,
                            },
                        );
                    }
                    let status = upstream_response.status();
                    let mut response_headers = upstream_response.headers().clone();
                    let mut body_bytes = match capture_context
                        .collect_response_body(upstream_response.into_body())
                        .await
                    {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            return record_http_error(HttpErrorContext {
                                targets: targets.clone(),
                                state,
                                id,
                                client_addr,
                                scheme: "fake_ip_https".to_string(),
                                method,
                                original_uri,
                                authority,
                                request_headers: request_headers_for_record,
                                request_body,
                                started,
                                request_started_at,
                                entry,
                                fake_addr,
                                upstream_addr: Some(upstream_addr),
                                err: anyhow!(
                                    "failed to read fake-IP HTTPS upstream response body: {err}"
                                ),
                            })
                            .await;
                        }
                    };
                    let mut discovered_tcp_targets = Vec::new();
                    match rewrite::apply(
                        state.response_rewrites(),
                        state.dns_registry(),
                        state.kubectl_proxy_manager(),
                        state.ca().ca_cert_pem_ref(),
                        state.config().recording.decoded_body_limit(),
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
                            targets.transformed(rewritten.transformation);
                            response_headers = rewritten.headers;
                            body_bytes = rewritten.body;
                            discovered_tcp_targets = rewritten.discovered_tcp_targets;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            return record_http_error(HttpErrorContext {
                                targets: targets.clone(),
                                state,
                                id,
                                client_addr,
                                scheme: "fake_ip_https".to_string(),
                                method,
                                original_uri,
                                authority,
                                request_headers: request_headers_for_record,
                                request_body,
                                started,
                                request_started_at,
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
                        outcome: crate::DependencyExchangeOutcome::Response,
                        id,
                        timestamp: Utc::now(),
                        request_started_at,
                        client_addr,
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
                        request_body: capture_body(
                            &request_body,
                            state.config().recording.max_body_bytes,
                        ),
                        response_status: Some(status.as_u16()),
                        response_headers: Some(response_headers_for_record),
                        response_body: Some(capture_body(
                            &body_bytes,
                            state.config().recording.max_body_bytes,
                        )),
                        response_stream: None,
                        discovered_tcp_targets,
                        duration_ms: started.elapsed().as_millis(),
                        error: None,
                    };
                    state.record_event_for_targets(
                        RecorderEvent::HttpExchange(event),
                        targets.clone(),
                    );

                    build_downstream_response(status, &response_headers, body_bytes)
                }
                Err(err) => {
                    if let Some(observed) = err.termination
                        && capture_context.forward_server_termination(observed)
                    {
                        return crate::recorder::http::dependency::closed_response();
                    }
                    record_http_error(HttpErrorContext {
                        targets: targets.clone(),
                        state,
                        id,
                        client_addr,
                        scheme: "fake_ip_https".to_string(),
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
                        request_started_at,
                        entry,
                        fake_addr,
                        upstream_addr: Some(upstream_addr),
                        err: anyhow!("fake-IP HTTPS client upstream request failed: {err}"),
                    })
                    .await
                }
            }
        })
        .await
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
