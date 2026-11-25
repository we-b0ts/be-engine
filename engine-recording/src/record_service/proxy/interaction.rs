//! Interaction-level reservations shared by polling requests and upgrades.

use brz_http_gateway::{AcquireOutcome, AdmissionProvider};
use std::{
    collections::HashMap,
    sync::{Mutex, Weak},
};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use super::*;
use crate::recorder::CaseInvalidation;
use transport::{TransportTasks, WeakTransportTasks};

mod tunnel;

#[derive(Clone)]
pub(super) struct InteractionRelay {
    state: crate::AppState,
    advertise: hyper::Uri,
    sessions: Arc<Mutex<Sessions>>,
}

#[derive(Default)]
struct Sessions {
    active: Option<Weak<CaseLease>>,
    sids: HashMap<String, Uuid>,
}

struct FiniteDelivery {
    finished: tokio::sync::oneshot::Receiver<()>,
    deadline: tokio::time::Instant,
}

struct CaseLease {
    case_id: Uuid,
    cancel: watch::Sender<bool>,
    _permit: OwnedSemaphorePermit,
    transports: Mutex<Vec<WeakTransportTasks>>,
}

impl CaseLease {
    fn track(&self, transport: &TransportTasks) {
        let next = transport.downgrade();
        let mut transports = self
            .transports
            .lock()
            .expect("case relay transports poisoned");
        transports.retain(|v| v.upgrade().is_some());
        if !transports.iter().any(|v| v.matches(&next)) {
            transports.push(next);
        }
        if *self.cancel.borrow() {
            transport.cancel();
        }
    }

    fn close(&self) {
        self.cancel.send_replace(true);
        for transport in self
            .transports
            .lock()
            .expect("case relay transports poisoned")
            .iter()
        {
            if let Some(transport) = transport.upgrade() {
                transport.cancel();
            }
        }
    }
}

impl InteractionRelay {
    pub(super) fn new(state: crate::AppState, advertise: hyper::Uri) -> Self {
        Self {
            state,
            advertise,
            sessions: Arc::new(Mutex::new(Sessions::default())),
        }
    }

    fn find(&self, sid: &str) -> Option<Arc<CaseLease>> {
        let sessions = self
            .sessions
            .lock()
            .expect("relay session registry poisoned");
        let active = sessions.active.as_ref()?.upgrade()?;
        (sessions.sids.get(sid) == Some(&active.case_id)).then_some(active)
    }

    fn bind(&self, sid: String, lease: &Arc<CaseLease>) {
        self.sessions
            .lock()
            .expect("relay session registry poisoned")
            .sids
            .insert(sid, lease.case_id);
    }
}

impl<R: Redis + Clone + 'static> Relay<R> {
    pub(super) async fn handle_interaction(
        &self,
        mut request: Request<Incoming>,
    ) -> Response<RelayBody> {
        let interaction = self
            .interactions
            .as_ref()
            .expect("interaction relay is configured");
        let sid = wire::socket_sid(&request);
        let mut lease = sid.as_deref().and_then(|sid| interaction.find(sid));
        if !self.ready.load(Ordering::SeqCst) && lease.is_none() {
            return response(StatusCode::SERVICE_UNAVAILABLE, "recorder unavailable");
        }
        let mut fresh = None;
        if sid.is_none() {
            let Ok(permit) = self.slot.clone().try_acquire_owned() else {
                return response(StatusCode::SERVICE_UNAVAILABLE, "recorder busy");
            };
            let ticket = match self.interaction_ticket(&request).await {
                Ok(ticket) => ticket,
                Err(message) => return response(StatusCode::SERVICE_UNAVAILABLE, message),
            };
            fresh = Some((permit, ticket));
        }
        request.headers_mut().remove(ADMISSION_SCOPE_HEADER);
        request.headers_mut().remove(ADMISSION_TOKEN_HEADER);
        let upgrade = wire::websocket(&request);
        let downstream_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
        let transports = request.extensions_mut().remove::<TransportTasks>();
        let (mut parts, body) = request.into_parts();
        let mut origin = self.origin.clone().into_parts();
        origin.path_and_query = parts.uri.path_and_query().cloned();
        parts.uri = match hyper::Uri::from_parts(origin) {
            Ok(uri) => uri,
            Err(_) => {
                if let Some((_, ticket)) = &fresh {
                    self.release(ticket).await;
                }
                return response(StatusCode::BAD_GATEWAY, "invalid recorder URI");
            }
        };
        wire::remove_hop_headers_with_upgrade(&mut parts.headers, upgrade);
        if !upgrade {
            parts.headers.insert(
                hyper::header::TE,
                hyper::header::HeaderValue::from_static("trailers"),
            );
            parts.headers.insert(
                hyper::header::CONNECTION,
                hyper::header::HeaderValue::from_static("TE"),
            );
        }
        let body = Limited::new(body, self.max_body).boxed_unsync();
        // Only the response head is bounded here. The inner interaction owner
        // enforces its business-idle, pending-work, duration and cleanup limits.
        let operation = tokio::time::timeout(
            self.timeout,
            self.client.request(Request::from_parts(parts, body)),
        );
        let pending_ticket = fresh.as_ref().and_then(|(_, ticket)| ticket.clone());
        let result = match self.with_pending_renewal(&pending_ticket, operation).await {
            Ok(result) => result,
            Err(()) => {
                return response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "recording reservation lost",
                );
            }
        };
        let mut upstream = match result {
            Ok(Ok(upstream)) => upstream,
            Ok(Err(error)) => {
                if let Some((_, ticket)) = &fresh {
                    if error.is_connect() {
                        self.release(ticket).await;
                    } else {
                        self.interaction_transport_failure(None);
                    }
                }
                return response(StatusCode::BAD_GATEWAY, "recorder stream request failed");
            }
            Err(_) => {
                self.interaction_transport_failure(None);
                return response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "recorder stream response head timed out",
                );
            }
        };
        let case_id = upstream
            .headers()
            .get(wire::CASE_ID)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<Uuid>().ok());
        if let Some((permit, ticket)) = fresh.take() {
            if let Some(case_id) = case_id {
                lease = Some(self.start_interaction_lease(case_id, permit, ticket, None));
            } else {
                // The inner Recorder rejected admission before creating a case.
                self.release(&ticket).await;
            }
        }
        if let (Some(lease), Some(case_id)) = (&lease, case_id) {
            if lease.case_id != case_id {
                self.interaction_transport_failure(Some(lease.case_id));
                return response(
                    StatusCode::BAD_GATEWAY,
                    "recorder session ownership changed",
                );
            }
            if let Some(sid) = upstream
                .headers()
                .get(wire::SESSION_ID)
                .and_then(|v| v.to_str().ok())
            {
                interaction.bind(sid.to_owned(), lease);
            }
        } else if case_id.is_some() {
            self.interaction_transport_failure(case_id);
            return response(
                StatusCode::BAD_GATEWAY,
                "recorder session reservation is missing",
            );
        }
        wire::strip_private(upstream.headers_mut());
        if let (Some(lease), Some(transports)) = (&lease, &transports) {
            lease.track(transports);
        }
        let cancel = lease.as_ref().map(|lease| lease.cancel.subscribe());
        if upstream.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(downstream_upgrade) = downstream_upgrade else {
                self.interaction_transport_failure(case_id);
                return response(StatusCode::BAD_GATEWAY, "unexpected recorder upgrade");
            };
            let upstream_upgrade = hyper::upgrade::on(&mut upstream);
            let tunnel = async move {
                let transfer = async {
                    let (downstream, upstream) =
                        tokio::try_join!(downstream_upgrade, upstream_upgrade)?;
                    tunnel::forward(downstream, upstream).await?;
                    Ok::<(), RelayError>(())
                };
                if let Some(mut cancel) = cancel {
                    tokio::select! {
                        result = transfer => { if let Err(error) = result { warn!(%error, "relay upgraded transport ended"); } }
                        _ = transport::cancelled(&mut cancel) => {}
                    }
                } else if let Err(error) = transfer.await {
                    warn!(%error, "relay upgraded transport ended");
                }
            };
            if let Some(transports) = transports {
                transports.spawn(tunnel);
            } else {
                tokio::spawn(tunnel);
            }
            let (parts, _) = upstream.into_parts();
            Response::from_parts(parts, full(Bytes::new()))
        } else {
            let (mut parts, body) = upstream.into_parts();
            wire::remove_response_hop_headers(&mut parts.headers);
            Response::from_parts(parts, transport::body(body, cancel))
        }
    }

    async fn interaction_ticket(
        &self,
        request: &Request<Incoming>,
    ) -> std::result::Result<Option<AdmissionTicket>, &'static str> {
        let Some(provider) = &self.reservations else {
            return Ok(None);
        };
        let scope = self.scope.as_deref().ok_or("reservation unavailable")?;
        let incoming = AdmissionTicket::from_headers(request.headers())
            .map_err(|_| "invalid recording admission")?;
        if let Some(ticket) = incoming {
            return match provider.owns(&ticket).await {
                Ok(true) if ticket.scope() == scope => Ok(Some(ticket)),
                _ => Err("reservation unavailable"),
            };
        }
        let acquired =
            tokio::time::timeout(Duration::from_millis(50), provider.try_acquire(scope)).await;
        let Ok(Ok(AcquireOutcome::Acquired(ticket))) = acquired else {
            return Err("recording reservation unavailable");
        };
        let advertise = &self.interactions.as_ref().unwrap().advertise;
        if ticket.origin().is_none_or(|origin| {
            origin.scheme() != advertise.scheme() || origin.authority() != advertise.authority()
        }) {
            self.release(&Some(ticket)).await;
            return Err("recording reservation belongs to another recorder");
        }
        Ok(Some(ticket))
    }

    pub(super) fn adopt_interaction_response(
        &self,
        upstream: Response<Incoming>,
        permit: OwnedSemaphorePermit,
        ticket: Option<AdmissionTicket>,
        transports: Option<TransportTasks>,
        deadline: tokio::time::Instant,
    ) -> Response<RelayBody> {
        let Some(case_id) = upstream
            .headers()
            .get(wire::CASE_ID)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<Uuid>().ok())
        else {
            self.interaction_transport_failure(None);
            return response(StatusCode::BAD_GATEWAY, "invalid recorder stream ownership");
        };
        let finite = upstream
            .headers()
            .get(wire::FINITE_RESPONSE)
            .is_some_and(|value| value == "1");
        let (body_finished, finished) = tokio::sync::oneshot::channel();
        let lease = self.start_interaction_lease(
            case_id,
            permit,
            ticket,
            finite.then_some(FiniteDelivery { finished, deadline }),
        );
        if let Some(transports) = transports {
            lease.track(&transports);
        }
        let (mut parts, body) = upstream.into_parts();
        wire::strip_private(&mut parts.headers);
        wire::remove_response_hop_headers(&mut parts.headers);
        let body = if finite {
            transport::finite_body(body, Some(lease.cancel.subscribe()), body_finished)
        } else {
            transport::body(body, Some(lease.cancel.subscribe()))
        };
        Response::from_parts(parts, body)
    }

    pub(super) async fn with_pending_renewal<F: std::future::Future>(
        &self,
        ticket: &Option<AdmissionTicket>,
        operation: F,
    ) -> std::result::Result<F::Output, ()> {
        if self.interactions.is_none() {
            return Ok(operation.await);
        }
        let (Some(reservations), Some(ticket)) = (&self.reservations, ticket) else {
            return Ok(operation.await);
        };
        // A bounded ordinary request body may have consumed most of the ticket
        // TTL before the response protocol became known. Recheck and extend it
        // before polling any upstream operation.
        if !matches!(reservations.renew(ticket).await, Ok(true)) {
            self.interaction_transport_failure(None);
            return Err(());
        }
        let mut timer = tokio::time::interval(reservations.reservation_ttl() / 3);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        timer.tick().await;
        tokio::pin!(operation);
        loop {
            tokio::select! {
                result = &mut operation => return Ok(result),
                _ = timer.tick() => {
                    if !matches!(reservations.renew(ticket).await, Ok(true)) {
                        self.interaction_transport_failure(None);
                        return Err(());
                    }
                }
            }
        }
    }

    fn start_interaction_lease(
        &self,
        case_id: Uuid,
        permit: OwnedSemaphorePermit,
        ticket: Option<AdmissionTicket>,
        delivery: Option<FiniteDelivery>,
    ) -> Arc<CaseLease> {
        let interaction = self.interactions.as_ref().unwrap().clone();
        let (cancel, _) = watch::channel(false);
        let lease = Arc::new(CaseLease {
            case_id,
            cancel,
            _permit: permit,
            transports: Mutex::new(Vec::new()),
        });
        interaction
            .sessions
            .lock()
            .expect("relay session registry poisoned")
            .active = Some(Arc::downgrade(&lease));
        let owned = lease.clone();
        let relay = self.clone();
        tokio::spawn(async move {
            let finite = delivery.is_some();
            let completed = interaction.state.wait_for_interaction_case(case_id);
            let delivery_deadline = delivery.as_ref().map(|delivery| delivery.deadline);
            let delivered = async {
                if let Some(delivery) = delivery {
                    let _ = delivery.finished.await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            let deadline = async {
                if let Some(deadline) = delivery_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::pin!(completed, delivered, deadline);
            let mut publication_done = false;
            let mut delivery_done = !finite;
            let renewal_period = relay
                .reservations
                .as_ref()
                .map_or(Duration::from_secs(1), |reservations| {
                    reservations.reservation_ttl() / 3
                });
            let mut timer = tokio::time::interval(renewal_period);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            timer.tick().await;
            loop {
                if publication_done && delivery_done {
                    break;
                }
                tokio::select! {
                    _ = &mut completed, if !publication_done => publication_done = true,
                    _ = &mut delivered, if !delivery_done => delivery_done = true,
                    _ = &mut deadline, if !delivery_done => {
                        // Only downstream delivery expires here. The Source
                        // owner and its case tail continue independently.
                        owned.close();
                        delivery_done = true;
                    },
                    _ = timer.tick(), if relay.reservations.is_some() && ticket.is_some() => {
                        let reservations = relay.reservations.as_ref().expect("renewal provider");
                        let ticket = ticket.as_ref().expect("renewal ticket");
                        if !matches!(reservations.renew(ticket).await, Ok(true)) {
                            relay.interaction_transport_failure(Some(case_id));
                            owned.close();
                            interaction.state.wait_for_interaction_case(case_id).await;
                            break;
                        }
                    }
                }
            }
            if !finite {
                owned.close();
            }
            relay.release(&ticket).await;
            let mut sessions = interaction
                .sessions
                .lock()
                .expect("relay session registry poisoned");
            sessions.sids.retain(|_, id| *id != case_id);
            if sessions
                .active
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|v| v.case_id == case_id)
            {
                sessions.active = None;
            }
        });
        lease
    }

    pub(super) fn interaction_transport_failure(&self, case_id: Option<Uuid>) {
        if let Some(interaction) = &self.interactions {
            let invalidated = interaction.state.invalidate_interaction_reservation(
                case_id,
                CaseInvalidation::new(
                    "interaction_reservation_lost",
                    "stream reservation or transport ownership was lost; Source requires isolation",
                ),
            );
            // Completion may win while a renewal is waiting on Redis. A loss
            // after the publication barrier cannot revoke that finished case
            // or disable recording for the next one.
            if case_id.is_some() && !invalidated {
                return;
            }
            self.close();
            interaction.state.begin_case_quiescing();
            interaction.state.close_interactions();
        } else {
            self.close();
        }
    }
}
