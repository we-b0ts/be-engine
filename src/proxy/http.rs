use std::convert::Infallible;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::http::uri::{Authority, PathAndQuery, Scheme};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::access_policy::AccessDecision;
use crate::http::access::classify_method;
use crate::http::forward::{HostHeaderPolicy, append_end_to_end_headers};
use crate::http::rewrite::{self, RewriteInput};
use crate::recorder::{
    HttpExchangeEvent, ProxyErrorEvent, RecorderEvent, capture_body, redact_headers,
};
use crate::recording_control::RecordingListener;
use crate::{AppState, ProxyClient};

type ProxyBody = BoxBody<Bytes, Infallible>;

pub async fn run(state: AppState) -> Result<()> {
    let listener = TcpListener::bind(state.config().http.listen)
        .await
        .with_context(|| format!("failed to bind HTTP proxy {}", state.config().http.listen))?;
    state.mark_recording_listener_ready(RecordingListener::HttpProxy);
    info!(listen = %state.config().http.listen, "HTTP/HTTPS proxy listening");

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept HTTP client")?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let client_addr = Some(peer_addr.to_string());
            let service = service_fn(move |req| {
                let state = state.clone();
                let client_addr = client_addr.clone();
                async move { Ok::<_, Infallible>(handle_proxy_request(req, state, client_addr).await) }
            });

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                warn!(error = %err, "HTTP proxy connection ended with error");
            }
        });
    }
}

async fn handle_proxy_request(
    req: Request<Incoming>,
    state: AppState,
    client_addr: Option<String>,
) -> Response<ProxyBody> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, state, client_addr).await;
    }

    forward_and_record(req, state, client_addr, "http", None).await
}

async fn handle_connect(
    req: Request<Incoming>,
    state: AppState,
    client_addr: Option<String>,
) -> Response<ProxyBody> {
    let authority = match connect_authority(req.uri()) {
        Some(authority) => authority,
        None => {
            return simple_response(StatusCode::BAD_REQUEST, "CONNECT request missing authority");
        }
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let target = authority.clone();
                if let Err(err) =
                    serve_mitm_connection(upgraded, authority, state.clone(), client_addr.clone())
                        .await
                {
                    error!(error = %err, "HTTPS MITM connection failed");
                    let _ = state
                        .recorder()
                        .record(RecorderEvent::ProxyError(ProxyErrorEvent {
                            id: Uuid::new_v4(),
                            timestamp: Utc::now(),
                            protocol: "https".to_string(),
                            client_addr,
                            target: Some(target),
                            error: err.to_string(),
                        }))
                        .await;
                }
            }
            Err(err) => {
                error!(error = %err, "failed to upgrade CONNECT tunnel");
            }
        }
    });

    simple_response(StatusCode::OK, "")
}

async fn serve_mitm_connection(
    upgraded: hyper::upgrade::Upgraded,
    authority: String,
    state: AppState,
    client_addr: Option<String>,
) -> Result<()> {
    let host = authority_host(&authority);
    let server_config = state.ca().server_config_for_host(&host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .with_context(|| format!("failed TLS handshake with client for {authority}"))?;

    let io = TokioIo::new(tls);
    let service = service_fn(move |req| {
        let state = state.clone();
        let client_addr = client_addr.clone();
        let authority = authority.clone();
        async move {
            Ok::<_, Infallible>(
                forward_and_record(req, state, client_addr, "https", Some(authority)).await,
            )
        }
    });

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .await
        .context("failed to serve decrypted HTTPS request")?;
    Ok(())
}

async fn forward_and_record(
    req: Request<Incoming>,
    state: AppState,
    client_addr: Option<String>,
    scheme: &str,
    fallback_authority: Option<String>,
) -> Response<ProxyBody> {
    let id = Uuid::new_v4();
    let started = Instant::now();
    let method = req.method().clone();
    let original_uri = req.uri().clone();
    let operation_class = classify_method(&method);
    if state.access_decision(operation_class) == AccessDecision::Reject {
        state
            .record_readonly_rejection(
                scheme,
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
        match state.recorder().capture_request_headers(&request_headers) {
            Ok(headers) => headers,
            Err(error) => {
                warn!(error = %error, "failed to protect recorded proxy request headers");
                return simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to protect recorded request headers",
                );
            }
        };

    let authority = original_uri
        .authority()
        .map(ToString::to_string)
        .or_else(|| fallback_authority.clone())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        });

    let request_body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                scheme: scheme.to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body: Bytes::new(),
                started,
                err: anyhow!("failed to read request body: {err}"),
            })
            .await;
        }
    };

    let outbound_uri = match make_upstream_uri(&original_uri, scheme, authority.as_deref()) {
        Ok(uri) => uri,
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                scheme: scheme.to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
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
    ) {
        Ok(req) => req,
        Err(err) => {
            return record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                scheme: scheme.to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
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
                        scheme: scheme.to_string(),
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
                        err: anyhow!("failed to read upstream response body: {err}"),
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
                    response_headers = rewritten.headers;
                    body_bytes = rewritten.body;
                    discovered_tcp_targets = rewritten.discovered_tcp_targets;
                }
                Ok(None) => {}
                Err(err) => {
                    return record_http_error(HttpErrorContext {
                        state,
                        id,
                        client_addr,
                        scheme: scheme.to_string(),
                        method,
                        original_uri,
                        authority,
                        request_headers: request_headers_for_record,
                        request_body,
                        started,
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
                scheme: scheme.to_string(),
                method: method.to_string(),
                uri: original_uri.to_string(),
                authority,
                request_headers: request_headers_for_record,
                request_body: capture_body(&request_body, state.config().recording.max_body_bytes),
                response_status: Some(status.as_u16()),
                response_headers: Some(response_headers_for_record),
                response_body: Some(capture_body(
                    &body_bytes,
                    state.config().recording.max_body_bytes,
                )),
                discovered_tcp_targets,
                duration_ms: started.elapsed().as_millis(),
                error: None,
            };
            record_event_and_case_dependency(&state, RecorderEvent::HttpExchange(event));

            build_downstream_response(status, &response_headers, body_bytes)
        }
        Err(err) => {
            record_http_error(HttpErrorContext {
                state,
                id,
                client_addr,
                scheme: scheme.to_string(),
                method,
                original_uri,
                authority,
                request_headers: request_headers_for_record,
                request_body,
                started,
                err: anyhow!("upstream request failed: {err}"),
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

struct HttpErrorContext {
    state: AppState,
    id: Uuid,
    client_addr: Option<String>,
    scheme: String,
    method: Method,
    original_uri: Uri,
    authority: Option<String>,
    request_headers: crate::recorder::HeaderMapSnapshot,
    request_body: Bytes,
    started: Instant,
    err: anyhow::Error,
}

async fn record_http_error(ctx: HttpErrorContext) -> Response<ProxyBody> {
    let error = format!("{:#}", ctx.err);
    let event = HttpExchangeEvent {
        id: ctx.id,
        timestamp: Utc::now(),
        client_addr: ctx.client_addr.clone(),
        scheme: ctx.scheme.clone(),
        method: ctx.method.to_string(),
        uri: ctx.original_uri.to_string(),
        authority: ctx.authority.clone(),
        request_headers: ctx.request_headers,
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
    record_event_and_case_dependency(&ctx.state, RecorderEvent::HttpExchange(event));
    record_event_and_case_dependency(
        &ctx.state,
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: ctx.scheme,
            client_addr: ctx.client_addr,
            target: ctx.authority,
            error: error.clone(),
        }),
    );
    simple_response(StatusCode::BAD_GATEWAY, &error)
}

fn record_event_and_case_dependency(state: &AppState, event: RecorderEvent) {
    state.record_event(event);
}

fn build_upstream_request(
    method: &Method,
    uri: Uri,
    body: Bytes,
    source_headers: &HeaderMap,
) -> Result<Request<Full<Bytes>>> {
    let mut builder = Request::builder().method(method).uri(uri);
    let headers = builder.headers_mut().expect("request builder headers");
    append_end_to_end_headers(source_headers, headers, HostHeaderPolicy::Preserve);
    builder
        .body(Full::new(body))
        .context("failed to build upstream request")
}

fn build_downstream_response(
    status: StatusCode,
    headers: &hyper::HeaderMap,
    body: Bytes,
) -> Response<ProxyBody> {
    let mut builder = Response::builder().status(status);
    let out_headers = builder.headers_mut().expect("response builder headers");
    append_end_to_end_headers(headers, out_headers, HostHeaderPolicy::Preserve);
    builder
        .body(boxed_body(body))
        .unwrap_or_else(|_| simple_response(StatusCode::BAD_GATEWAY, "failed to build response"))
}

fn simple_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(boxed_body(Bytes::copy_from_slice(body.as_bytes())))
        .expect("valid static response")
}

fn boxed_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).boxed()
}

fn make_upstream_uri(uri: &Uri, scheme: &str, authority: Option<&str>) -> Result<Uri> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }

    let scheme = Scheme::try_from(scheme).context("invalid upstream scheme")?;
    let authority = authority.ok_or_else(|| anyhow!("request missing authority/host"))?;
    let authority = Authority::try_from(authority).context("invalid upstream authority")?;
    let path_and_query = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));

    let mut parts = hyper::http::uri::Parts::default();
    parts.scheme = Some(scheme);
    parts.authority = Some(authority);
    parts.path_and_query = Some(path_and_query);
    Uri::from_parts(parts).context("failed to construct upstream URI")
}

fn connect_authority(uri: &Uri) -> Option<String> {
    uri.authority().map(ToString::to_string).or_else(|| {
        let path = uri.path();
        (!path.is_empty()).then(|| path.to_string())
    })
}

fn authority_host(authority: &str) -> String {
    if let Some(stripped) = authority
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|parts| parts.0))
    {
        return stripped.to_string();
    }
    authority.split(':').next().unwrap_or(authority).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_absolute_uri_from_origin_form() {
        let uri = "/hello?x=1".parse::<Uri>().unwrap();
        let upstream = make_upstream_uri(&uri, "https", Some("example.com:443")).unwrap();
        assert_eq!(upstream.to_string(), "https://example.com:443/hello?x=1");
    }
}
