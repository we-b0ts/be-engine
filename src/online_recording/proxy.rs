//! Reservation-aware forwarding. Case completion follows Recorder's full response.

use anyhow::{Context, Result};
use brz_http_gateway::redis_admission::RedisAdmissionProvider;
use brz_http_gateway::{ADMISSION_SCOPE_HEADER, ADMISSION_TOKEN_HEADER, AdmissionTicket};
use brz_redis::Redis;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tracing::warn;

#[derive(Clone)]
pub(super) struct Relay<R> {
    reservations: RedisAdmissionProvider<R>,
    client: Client<HttpConnector, Full<Bytes>>,
    origin: hyper::Uri,
    scope: String,
    ready: Arc<AtomicBool>,
    slot: Arc<Semaphore>,
    timeout: Duration,
    max_body: usize,
}

impl<R: Redis + Clone + 'static> Relay<R> {
    pub(super) fn new(
        reservations: RedisAdmissionProvider<R>,
        origin: hyper::Uri,
        scope: String,
        timeout: Duration,
        max_body: usize,
    ) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(1)));
        Self {
            reservations,
            client: Client::builder(TokioExecutor::new()).build(connector),
            origin,
            scope,
            ready: Arc::new(AtomicBool::new(false)),
            slot: Arc::new(Semaphore::new(1)),
            timeout,
            max_body,
        }
    }

    pub(super) fn open(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }
    pub(super) fn close(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }
    pub(super) async fn drain(&self) {
        let _permit = self.slot.acquire().await;
    }

    async fn release(&self, ticket: &AdmissionTicket) {
        if let Err(error) = self.reservations.complete(ticket).await {
            warn!(%error, "recording slot release failed; TTL will recover it");
        }
    }

    async fn handle(&self, mut request: Request<Incoming>) -> Response<Full<Bytes>> {
        let ticket = match AdmissionTicket::from_headers(request.headers()) {
            Ok(Some(ticket)) if ticket.scope() == self.scope => ticket,
            _ => return response(StatusCode::NOT_FOUND, "recording admission required"),
        };
        request.headers_mut().remove(ADMISSION_SCOPE_HEADER);
        request.headers_mut().remove(ADMISSION_TOKEN_HEADER);
        let Ok(_permit) = self.slot.clone().try_acquire_owned() else {
            // Do not release an identical replay of the currently executing token.
            return response(StatusCode::NOT_FOUND, "recorder busy");
        };
        match self.reservations.owns(&ticket).await {
            Ok(true) => {}
            _ => return response(StatusCode::NOT_FOUND, "reservation unavailable"),
        }
        if !self.ready.load(Ordering::SeqCst) {
            self.release(&ticket).await;
            return response(StatusCode::NOT_FOUND, "recorder unavailable");
        }
        let (mut parts, body) = request.into_parts();
        let body =
            match tokio::time::timeout(self.timeout, Limited::new(body, self.max_body).collect())
                .await
            {
                Ok(Ok(body)) => body.to_bytes(),
                _ => {
                    self.release(&ticket).await;
                    return response(StatusCode::NOT_FOUND, "request cannot be recorded");
                }
            };
        let mut uri = self.origin.clone().into_parts();
        uri.path_and_query = parts.uri.path_and_query().cloned();
        parts.uri = match hyper::Uri::from_parts(uri) {
            Ok(uri) => uri,
            Err(_) => {
                self.release(&ticket).await;
                return response(StatusCode::NOT_FOUND, "invalid request URI");
            }
        };
        remove_hop_headers(&mut parts.headers);
        if !self.ready.load(Ordering::SeqCst) {
            self.release(&ticket).await;
            return response(StatusCode::NOT_FOUND, "recorder unavailable");
        }
        let request = Request::from_parts(parts, Full::new(body));
        let result = tokio::time::timeout(self.timeout, async {
            let response = match self.client.request(request).await {
                Ok(response) => response,
                Err(error) if error.is_connect() => return Ok(None),
                Err(error) => return Err(anyhow::Error::new(error)),
            };
            let (mut parts, body) = response.into_parts();
            let body = body.collect().await?.to_bytes();
            remove_hop_headers(&mut parts.headers);
            Ok(Some(Response::from_parts(parts, Full::new(body))))
        })
        .await;
        match result {
            Ok(Ok(Some(response))) => {
                self.release(&ticket).await;
                response
            }
            Ok(Ok(None)) => {
                self.release(&ticket).await;
                response(StatusCode::NOT_FOUND, "recorder unreachable")
            }
            Ok(Err(error)) => {
                warn!(%error, "recorder response failed; reservation retained");
                response(StatusCode::BAD_GATEWAY, "recorder response failed")
            }
            Err(_) => response(StatusCode::GATEWAY_TIMEOUT, "recorder request timed out"),
        }
    }
}

pub(super) async fn serve<R: Redis + Clone + 'static>(
    listener: TcpListener,
    relay: Relay<R>,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut stopping = stop.clone();
    loop {
        tokio::select! {
            changed = stopping.changed() => { changed.ok(); break; }
            joined = tasks.join_next(), if !tasks.is_empty() => { if let Some(Err(error)) = joined { warn!(%error, "online recording connection failed"); } }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("online recording accept failed")?;
                let relay = relay.clone();
                let mut stopping = stop.clone();
                tasks.spawn(async move {
                    let service = service_fn(move |request| {
                        let relay = relay.clone();
                        async move {
                            // Keep the upstream operation alive if the downstream disconnects.
                            let result = tokio::spawn(async move { relay.handle(request).await }).await;
                            Ok::<_, Infallible>(result.unwrap_or_else(|_| response(StatusCode::BAD_GATEWAY, "recording request task failed")))
                        }
                    });
                    let connection = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        result = &mut connection => { if let Err(error) = result { warn!(%error, "online recording HTTP connection ended"); } }
                        _ = stopping.changed() => { connection.as_mut().graceful_shutdown(); let _ = connection.await; }
                    }
                });
            }
        }
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn response(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(message.as_bytes())))
        .unwrap()
}

fn remove_hop_headers(headers: &mut hyper::HeaderMap) {
    let named: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim))
        .filter_map(|name| name.parse::<hyper::header::HeaderName>().ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
