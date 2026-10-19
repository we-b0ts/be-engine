//! Reservation-aware forwarding, with one lease per full interaction case.

use anyhow::{Context, Result};
use brz_http_gateway::redis_admission::RedisAdmissionProvider;
use brz_http_gateway::{ADMISSION_SCOPE_HEADER, ADMISSION_TOKEN_HEADER, AdmissionTicket};
use brz_redis::Redis;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, combinators::UnsyncBoxBody};
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

mod interaction;
mod listener;
mod ordinary;
#[cfg(test)]
mod tests;
mod transport;
mod wire;

use interaction::InteractionRelay;
pub(super) use listener::serve;
use wire::{full, remove_hop_headers, response};

type RelayError = Box<dyn std::error::Error + Send + Sync>;
type RelayBody = UnsyncBoxBody<Bytes, RelayError>;

#[derive(Clone)]
pub(super) struct Relay<R> {
    reservations: Option<RedisAdmissionProvider<R>>,
    client: Client<HttpConnector, RelayBody>,
    origin: hyper::Uri,
    scope: String,
    ready: Arc<AtomicBool>,
    slot: Arc<Semaphore>,
    timeout: Duration,
    max_body: usize,
    interactions: Option<InteractionRelay>,
}

impl<R: Redis + Clone + 'static> Relay<R> {
    pub(super) fn new(
        reservations: Option<RedisAdmissionProvider<R>>,
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
            interactions: None,
        }
    }

    pub(super) fn with_interactions(
        mut self,
        state: crate::AppState,
        advertise: hyper::Uri,
    ) -> Self {
        self.interactions = Some(InteractionRelay::new(state, advertise));
        self
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

    async fn release(&self, ticket: &Option<AdmissionTicket>) {
        let (Some(reservations), Some(ticket)) = (&self.reservations, ticket) else {
            return;
        };
        if let Err(error) = reservations.complete(ticket).await {
            warn!(%error, "recording slot release failed; TTL will recover it");
        }
    }

    async fn handle(&self, mut request: Request<Incoming>) -> Response<RelayBody> {
        wire::strip_private(request.headers_mut());
        if self.interactions.is_some() && wire::is_interaction(&request) {
            self.handle_interaction(request).await
        } else {
            self.handle_ordinary(request).await
        }
    }
}
