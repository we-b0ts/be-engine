//! Streaming relay and reservation lifetime for concurrent session ingress.
use std::collections::HashSet;
use std::sync::Mutex;

use http_body::Body as _;
use http_body_util::StreamBody;
use tokio::sync::OwnedSemaphorePermit;

use super::*;
use crate::gateway::http::SESSION_UPGRADE_HEADER;

#[derive(Clone)]
pub(super) struct SessionRelay {
    app: crate::AppState,
    active_tickets: Arc<Mutex<HashSet<String>>>,
}

impl SessionRelay {
    pub(super) fn new(app: crate::AppState) -> Self {
        Self {
            app,
            active_tickets: Default::default(),
        }
    }
}

impl<R: Redis + Clone + 'static> Relay<R> {
    pub(super) async fn handle_session(
        &self,
        mut request: Request<Incoming>,
        session: &SessionRelay,
    ) -> Response<RelayBody> {
        let Ok(permit) = self.slot.clone().try_acquire_owned() else {
            return response(StatusCode::SERVICE_UNAVAILABLE, "session recorder busy");
        };

        let ticket = if let Some(provider) = &self.reservations {
            let Ok(Some(ticket)) = AdmissionTicket::from_headers(request.headers()) else {
                return response(StatusCode::NOT_FOUND, "recording admission required");
            };
            if ticket.scope() != self.scope {
                return response(StatusCode::NOT_FOUND, "recording reservation unavailable");
            }
            let Some(mut lease) = Lease::admit(provider.clone(), ticket, session) else {
                return response(
                    StatusCode::NOT_FOUND,
                    "recording reservation already in use",
                );
            };
            if !lease.renew().await {
                return response(StatusCode::NOT_FOUND, "recording reservation unavailable");
            }
            lease.start_renewal();
            Some(lease)
        } else {
            None
        };
        if !self.ready.load(Ordering::SeqCst) {
            return response(StatusCode::NOT_FOUND, "recorder unavailable");
        }

        request.headers_mut().remove(ADMISSION_SCOPE_HEADER);
        request.headers_mut().remove(ADMISSION_TOKEN_HEADER);
        if request.headers().contains_key(hyper::header::UPGRADE)
            || request.method() == hyper::Method::CONNECT
        {
            // Leave the classification to the Source-facing gateway. It can
            // reject an excluded route before treating an upgrade as unsupported.
            request.headers_mut().insert(
                SESSION_UPGRADE_HEADER,
                hyper::header::HeaderValue::from_static("1"),
            );
        } else {
            request.headers_mut().remove(SESSION_UPGRADE_HEADER);
        }
        let mut origin = self.origin.clone().into_parts();
        origin.path_and_query = request.uri().path_and_query().cloned();
        match hyper::Uri::from_parts(origin) {
            Ok(uri) => *request.uri_mut() = uri,
            Err(_) => return response(StatusCode::BAD_REQUEST, "invalid request URI"),
        }
        remove_hop_headers(request.headers_mut());
        request.headers_mut().insert(
            hyper::header::TE,
            hyper::header::HeaderValue::from_static("trailers"),
        );
        request.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("TE"),
        );
        let mut admission = Admission {
            _permit: permit,
            lease: ticket,
        };
        let request = request.map(|body| {
            body.map_err(|error| Box::new(error) as RelayError)
                .boxed_unsync()
        });
        let upstream = tokio::select! {
            upstream = self.client.request(request) => upstream,
            _ = admission.lease_lost() => return response(StatusCode::SERVICE_UNAVAILABLE, "recording reservation lost"),
        };
        let upstream = match upstream {
            Ok(response) => response,
            Err(error) => {
                session
                    .app
                    .fail_session_recording("session relay could not forward admitted request");
                warn!(%error, "session relay could not forward admitted request");
                return response(StatusCode::BAD_GATEWAY, "session recorder transport failed");
            }
        };
        let (mut parts, body) = upstream.into_parts();
        wire::remove_response_hop_headers(&mut parts.headers);
        wire::strip_private(&mut parts.headers);
        if body.is_end_stream() {
            return Response::from_parts(parts, full(Bytes::new()));
        }
        let frames = futures_util::stream::unfold(Some((body, admission)), |pending| async move {
            let (mut body, mut admission) = pending?;
            let frame = tokio::select! {
                frame = body.frame() => frame.map(|frame| frame.map_err(|error| Box::new(error) as RelayError)),
                _ = admission.lease_lost() => Some(Err(std::io::Error::other("recording reservation lost").into())),
            };
            frame.map(|frame| {
                let pending = (frame.is_ok() && !body.is_end_stream()).then_some((body, admission));
                (frame, pending)
            })
        });
        Response::from_parts(parts, StreamBody::new(frames).boxed_unsync())
    }
}

struct Admission<R: Redis + Clone + 'static> {
    _permit: OwnedSemaphorePermit,
    lease: Option<Lease<R>>,
}

impl<R: Redis + Clone + 'static> Admission<R> {
    async fn lease_lost(&mut self) {
        if let Some(lease) = &mut self.lease {
            if !*lease.lost.borrow() {
                let _ = lease.lost.changed().await;
            }
        } else {
            std::future::pending().await
        }
    }
}

struct Lease<R: Redis + Clone + 'static> {
    provider: RedisAdmissionProvider<R>,
    ticket: AdmissionTicket,
    session: SessionRelay,
    lost: watch::Receiver<bool>,
    renewal: Option<tokio::task::JoinHandle<()>>,
}

impl<R: Redis + Clone + 'static> Lease<R> {
    fn admit(
        provider: RedisAdmissionProvider<R>,
        ticket: AdmissionTicket,
        session: &SessionRelay,
    ) -> Option<Self> {
        let token = ticket.token().to_owned();
        if !session
            .active_tickets
            .lock()
            .expect("session tickets poisoned")
            .insert(token)
        {
            return None;
        }
        Some(Self {
            provider,
            ticket,
            session: session.clone(),
            lost: watch::channel(false).1,
            renewal: None,
        })
    }

    async fn renew(&self) -> bool {
        matches!(self.provider.renew(&self.ticket).await, Ok(true))
    }

    fn start_renewal(&mut self) {
        let (lost, receiver) = watch::channel(false);
        self.lost = receiver;
        let provider = self.provider.clone();
        let ticket = self.ticket.clone();
        let app = self.session.app.clone();
        self.renewal = Some(tokio::spawn(async move {
            let mut timer = tokio::time::interval(provider.reservation_ttl() / 3);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            timer.tick().await;
            loop {
                timer.tick().await;
                if !matches!(provider.renew(&ticket).await, Ok(true)) {
                    app.fail_session_recording("lost admitted session recording reservation");
                    lost.send_replace(true);
                    break;
                }
            }
        }));
    }
}

impl<R: Redis + Clone + 'static> Drop for Lease<R> {
    fn drop(&mut self) {
        if let Some(renewal) = self.renewal.take() {
            renewal.abort();
        }
        let provider = self.provider.clone();
        let ticket = self.ticket.clone();
        let tickets = self.session.active_tickets.clone();
        tokio::spawn(async move {
            if let Err(error) = provider.complete(&ticket).await {
                warn!(%error, "session recorder reservation release failed; TTL will recover it");
            }
            tickets
                .lock()
                .expect("session tickets poisoned")
                .remove(ticket.token());
        });
    }
}
