//! Native drivers submit requests while the host owns matching and actual delivery.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use traffic_protocol::{
    connection::{
        ConnectionInfo, ConnectionIo, NativeFuture, RejectedCommand, ReplaySessionStep,
        RequestHost, RequestSession, ResponseDelivery, ResponseFramer,
    },
    message::ProtocolMessage,
};

pub(crate) async fn handle_connection<P: ReplayProtocolSet>(
    stream: TcpStream,
    peer: SocketAddr,
    target: ReplayTarget,
    state: Arc<Mutex<RuntimeState<P>>>,
) -> Result<()> {
    let connection_protocol = target.protocol.id();
    let endpoint = Endpoint {
        host: target.host,
        port: target.port,
    };
    let (protocol, session) = {
        let state = state.lock().await;
        let entry = state.providers.connection_provider(connection_protocol)?;
        let session = entry
            .provider
            .native_protocol()
            .context("registered dependency has no native connection capability")?
            .server_session(ConnectionInfo {
                endpoint: endpoint.clone(),
                client_addr: Some(peer.to_string()),
                upstream_addr: None,
                max_frame_bytes: traffic_contract::MAX_VALUE_BYTES,
            })?;
        (entry.kind.id(), session)
    };
    let state_bindings = state.lock().await.native.core.sessions.clone();
    let host = Arc::new(Host {
        state,
        protocol,
        endpoint,
        reported: Arc::new(AtomicBool::new(false)),
        delivered: Default::default(),
        session: Uuid::new_v4(),
        bindings: state_bindings,
    });
    let result = session.run(Box::new(stream), host.clone()).await;
    if let Err(error) = &result
        && !host.reported.swap(true, Ordering::AcqRel)
    {
        let mut state = host.state.lock().await;
        if state.finalized_at.is_none() {
            let case = state.active_case_id.clone();
            state.native.record_failure(
                protocol,
                &host.endpoint,
                case,
                None,
                None,
                &error.to_string(),
                Default::default(),
            );
        }
    }
    result
}

#[derive(Clone)]
struct DeliveredAnchor {
    started: tokio::time::Instant,
    lane: Option<String>,
    owner: request::SessionOwner,
}

pub(super) struct Host<P: ReplayProtocolSet> {
    state: Arc<Mutex<RuntimeState<P>>>,
    session: Uuid,
    bindings: traffic_replay::exchange::SessionBindings,
    protocol: ProtocolId,
    endpoint: Endpoint,
    reported: Arc<AtomicBool>,
    delivered: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<traffic_model::recording::ProtocolRef, DeliveredAnchor>,
        >,
    >,
}

impl<P: ReplayProtocolSet> Drop for Host<P> {
    fn drop(&mut self) {
        // Task cancellation also ends the physical session, even when the
        // native driver cannot return through its ordinary connection exit.
        self.bindings.release(self.session);
    }
}

impl<P: ReplayProtocolSet> RequestHost for Host<P> {
    fn release_session(&self) {
        self.bindings.release(self.session);
    }

    fn reject_command<'a>(
        &'a self,
        command: RejectedCommand<'a>,
        session: RequestSession,
    ) -> NativeFuture<'a, String> {
        Box::pin(async move {
            let observed = Utc::now();
            let mut state = self.state.lock().await;
            if state.finalized_at.is_some() {
                return Ok(command.reason(None));
            }
            let case = state.active_case_id.clone();
            let expected = self.session_owner(Some(&session)).ok().and_then(|owner| {
                state
                    .native
                    .core
                    .expected_request(self.protocol, &self.endpoint, case.as_deref(), &session)
                    .filter(|exchange| {
                        owner.as_ref().is_none_or(|owner| {
                            owner
                                .epoch
                                .is_none_or(|epoch| epoch == state.admission_epoch)
                                && owner.scope == exchange.source.source
                                && owner.case == exchange.source.case_id
                        })
                    })
            });
            let capture = expected.and_then(|exchange| exchange.source.capture.as_ref());
            let expected_command = expected
                .and_then(|exchange| exchange.native.request())
                .and_then(ProtocolMessage::command_name);
            let reason = command.reason(expected_command);
            let diagnostics = diagnosis::CandidateDiagnostics {
                command_mismatch: Some(diagnosis::CommandMismatch {
                    expected: expected_command.map(str::to_owned),
                    received: command.received.to_owned(),
                    source_dependency_sequence: capture.map(|capture| capture.sequence),
                    source_reference: expected.map(|exchange| exchange.native.reference.clone()),
                    source_exchange_id: capture.map(|capture| capture.exchange_id),
                }),
                ..Default::default()
            };
            let event = state.native.order.reserve(case.as_deref());
            let id = Uuid::new_v4();
            let retention = state.target_observations.record(
                id,
                case.as_deref(),
                None,
                self.protocol.as_str(),
                observed,
                &command.observation,
            );
            let observation = state.target_observations.retained(&retention).then_some(id);
            state.native.record_failure(
                self.protocol,
                &self.endpoint,
                case,
                Some(event),
                observation,
                &reason,
                diagnostics,
            );
            self.reported.store(true, Ordering::Release);
            Ok(reason)
        })
    }

    fn execute_bound(
        &self,
        message: Arc<dyn ProtocolMessage>,
        after: Option<traffic_model::recording::ProtocolRef>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        self.execute_required(message, Some(after), None)
    }
    fn execute_in_session(
        &self,
        message: Arc<dyn ProtocolMessage>,
        session: RequestSession,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        self.execute_required(message, None, Some(session))
    }
    fn try_execute_session_control(
        &self,
        message: Arc<dyn ProtocolMessage>,
        session: RequestSession,
    ) -> NativeFuture<'_, Option<Box<dyn ResponseDelivery>>> {
        Box::pin(self.execute_request(message, None, Some(session), true))
    }
    fn forget_anchor(&self, reference: &traffic_model::recording::ProtocolRef) {
        self.delivered
            .lock()
            .expect("native delivery anchors")
            .remove(reference);
    }
    fn next_message(
        &self,
        anchors: Vec<traffic_model::recording::ProtocolRef>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            ensure!(
                !anchors.is_empty() && anchors.len() <= 256,
                "native message anchor budget exceeded"
            );
            loop {
                let (changed, mut sequence) = {
                    let mut state = self.state.lock().await;
                    ensure!(
                        state.finalized_at.is_none() && !state.target_session_stopped,
                        "Replay session stopped before native message delivery"
                    );
                    let changed = state.native.core.lifecycle.subscribe();
                    let sequence = state.native.core.lifecycle.sequence.subscriptions();
                    let delivered = self.delivered.lock().expect("native delivery anchors");
                    ensure!(
                        anchors.iter().all(|anchor| delivered.contains_key(anchor)),
                        "native emission anchor has no successful delivery on this connection"
                    );
                    if !state.async_case_quiescing()
                        && let Some(index) = state.native.core.select_message(
                            self.protocol,
                            &self.endpoint,
                            state.active_case_id.as_deref(),
                            &anchors,
                        )
                    {
                        let traffic_protocol::connection::RecordedInput::Emission { after, offset } =
                            &state.native.core.exchanges[index].native.input
                        else {
                            unreachable!("native emission")
                        };
                        let started = delivered[after]
                            .started
                            .checked_add(*offset)
                            .context("native message clock overflow")?;
                        let case = state.native.core.exchanges[index].source.case_id.clone();
                        let run_owned = state.native.core.exchanges[index]
                            .source
                            .source
                            .is_run_owned();
                        let ticket = state.native.core.claim(index)?;
                        let guard = ticket.guard();
                        let matched = request::Matched {
                            index,
                            ticket,
                            observed: Utc::now(),
                            delay: Default::default(),
                            case,
                            epoch: state.admission_epoch,
                            run_owned,
                        };
                        return Ok(Box::new(Delivery {
                            retain_anchor: false,
                            session_step: None,
                            reference: state.native.core.exchanges[index].native.reference.clone(),
                            matched,
                            started,
                            state: self.state.clone(),
                            protocol: self.protocol,
                            endpoint: self.endpoint.clone(),
                            reported: self.reported.clone(),
                            _guard: guard,
                            delivered: self.delivered.clone(),
                        }) as Box<dyn ResponseDelivery>);
                    }
                    (changed, sequence)
                };
                use futures_util::{StreamExt, stream::FuturesUnordered};
                let mut changes: FuturesUnordered<_> = sequence
                    .iter_mut()
                    .map(|receiver| receiver.changed())
                    .collect();
                tokio::select! {
                    _ = changed.changed() => {},
                    _ = changes.next(), if !changes.is_empty() => {},
                }
            }
        })
    }

    fn begin_input(&self) -> NativeFuture<'_, Box<dyn traffic_protocol::connection::RequestInput>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            ensure!(
                state.finalized_at.is_none(),
                "Replay session is already finalized"
            );
            Ok(
                Box::new(state.native.inputs.begin(state.active_case_id.clone()))
                    as Box<dyn traffic_protocol::connection::RequestInput>,
            )
        })
    }
    fn accept_tls(
        &self,
        io: Box<dyn ConnectionIo>,
        alpn: Vec<Vec<u8>>,
    ) -> NativeFuture<'_, Box<dyn ConnectionIo>> {
        Box::pin(async move {
            let tls = self
                .state
                .lock()
                .await
                .native
                .tls
                .clone()
                .context("native server TLS is unavailable")?;
            tls.accept(io, self.endpoint.host.clone(), alpn).await
        })
    }
    fn execute(
        &self,
        message: Arc<dyn ProtocolMessage>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        self.execute_required(message, None, None)
    }
}

impl<P: ReplayProtocolSet> Host<P> {
    fn session_owner(
        &self,
        session: Option<&RequestSession>,
    ) -> Result<Option<request::SessionOwner>> {
        session
            .and_then(|session| session.after.as_ref())
            .map(|after| {
                self.delivered
                    .lock()
                    .expect("native delivery anchors")
                    .get(after)
                    .context("native transaction predecessor was not delivered on this connection")
                    .map(|anchor| anchor.owner.clone())
            })
            .transpose()
    }

    fn execute_required(
        &self,
        message: Arc<dyn ProtocolMessage>,
        binding: Option<Option<traffic_model::recording::ProtocolRef>>,
        request_session: Option<RequestSession>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            self.execute_request(message, binding, request_session, false)
                .await?
                .context("required native delivery missing")
        })
    }

    async fn execute_request(
        &self,
        message: Arc<dyn ProtocolMessage>,
        binding: Option<Option<traffic_model::recording::ProtocolRef>>,
        request_session: Option<RequestSession>,
        optional_control: bool,
    ) -> Result<Option<Box<dyn ResponseDelivery>>> {
        let started = tokio::time::Instant::now();
        let observed = Utc::now();
        let bytes = message
            .project()?
            .values
            .values()
            .try_fold(0_usize, |size, value| {
                size.checked_add(value.bytes.len())
                    .context("native request size overflow")
            })?;
        ensure!(
            bytes <= traffic_contract::MAX_VALUE_BYTES,
            "native request exceeds the value byte bound"
        );
        let lane = binding
            .as_ref()
            .and_then(|binding| binding.as_ref())
            .map(|reference| {
                self.delivered
                    .lock()
                    .expect("native delivery anchors")
                    .get(reference)
                    .and_then(|anchor| anchor.lane.clone())
                    .context(
                        "native session continuation has no successful delivery on this connection",
                    )
            })
            .transpose()?;
        let session_owner = self.session_owner(request_session.as_ref())?;
        let mut request = request::Request {
            protocol: self.protocol,
            endpoint: self.endpoint.clone(),
            message,
            session: binding.is_some().then_some(self.session),
            lane,
            request_session,
            session_owner,
            optional_control,
            observed,
            bytes,
            diagnostics: Default::default(),
        };
        let matched = admission::request::execute(
            &self.state,
            &mut request,
            tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        )
        .await;
        let matched = match matched {
            Ok(matched) => matched,
            Err(error) if optional_control && error.kind == request::RejectionKind::NoMatch => {
                return Ok(None);
            }
            Err(error) => {
                self.reported.store(true, Ordering::Release);
                return Err(error.into());
            }
        };
        let guard = matched.ticket.guard();
        let (reference, session_step) = {
            let state = self.state.lock().await;
            let exchange = &state.native.core.exchanges[matched.index];
            (
                exchange.native.reference.clone(),
                exchange.session_step.clone(),
            )
        };
        Ok(Some(Box::new(Delivery {
            retain_anchor: false,
            session_step,
            reference,
            matched,
            started,
            state: self.state.clone(),
            protocol: self.protocol,
            endpoint: self.endpoint.clone(),
            reported: self.reported.clone(),
            _guard: guard,
            delivered: self.delivered.clone(),
        }) as Box<dyn ResponseDelivery>))
    }
}

struct Delivery<P: ReplayProtocolSet> {
    retain_anchor: bool,
    session_step: Option<ReplaySessionStep>,
    reference: traffic_model::recording::ProtocolRef,
    matched: request::Matched,
    started: tokio::time::Instant,
    state: Arc<Mutex<RuntimeState<P>>>,
    protocol: ProtocolId,
    endpoint: Endpoint,
    reported: Arc<AtomicBool>,
    _guard: admission::DeliveryGuard,
    delivered: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<traffic_model::recording::ProtocolRef, DeliveredAnchor>,
        >,
    >,
}

impl<P: ReplayProtocolSet> Delivery<P> {
    async fn wait_ready(&self) -> Result<()> {
        self.matched.ticket.wait_sequence_delivery().await?;
        loop {
            let (changed, due, fast) =
                {
                    let state = self.state.lock().await;
                    ensure!(
                        state.finalized_at.is_none()
                            && !state.target_session_stopped
                            && (self.matched.run_owned
                                || state.admission_epoch == self.matched.epoch
                                    && state.active_case_id == self.matched.case
                                    && !state.async_case_quiescing()
                                    && self.matched.case.as_ref().is_none_or(|case| !state
                                        .target_stop_prepared
                                        .contains(case))),
                        "native response owner stopped before delivery"
                    );
                    (
                        state.native.core.lifecycle.subscribe(),
                        self.started
                            .checked_add(self.matched.delay)
                            .context("native delivery clock overflow")?,
                        state.stream_timing == Some(ReplayStreamTiming::Fast),
                    )
                };
            if fast || tokio::time::Instant::now() >= due {
                return Ok(());
            }
            tokio::select! {
                _ = tokio::time::sleep_until(due) => {},
                _ = changed.changed() => {},
            }
        }
    }
}

impl<P: ReplayProtocolSet> ResponseDelivery for Delivery<P> {
    fn ready(&mut self) -> NativeFuture<'_, ()> {
        Box::pin(self.wait_ready())
    }
    fn retain_as_anchor(&mut self) {
        self.retain_anchor = true;
    }
    fn reference(&self) -> Option<traffic_model::recording::ProtocolRef> {
        Some(self.reference.clone())
    }
    fn session_step(&self) -> Option<&ReplaySessionStep> {
        self.session_step.as_ref()
    }

    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn traffic_protocol::connection::OutputIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let matched = &self.matched;
            let result = async {
                self.wait_ready().await?;
                let response = self.state.lock().await.native.core.exchanges[matched.index]
                    .native
                    .response
                    .clone();
                let loaded = if response.stored().is_some() {
                    Some(
                        tokio::task::spawn_blocking(move || {
                            response.stored().expect("stored response").load()
                        })
                        .await
                        .context("Source response read failed")??,
                    )
                } else {
                    None
                };
                let response = {
                    let state = self.state.lock().await;
                    ensure!(
                        state.finalized_at.is_none()
                            && !state.target_session_stopped
                            && (matched.run_owned
                                || state.admission_epoch == matched.epoch
                                    && state.active_case_id == matched.case
                                    && !state.async_case_quiescing()
                                    && matched.case.as_ref().is_none_or(|case| !state
                                        .target_stop_prepared
                                        .contains(case))),
                        "native response owner stopped before delivery"
                    );
                    state.native.render_response(
                        matched.index,
                        matched.observed,
                        loaded.as_deref(),
                    )?
                };
                let request::ResponsePlan {
                    output: response,
                    comparison,
                    identity,
                } = response;
                let response = framer.prepare_output(response)?;
                let mut output = traffic_protocol::output::FramedOutput::new(response, framer);
                traffic_replay::output::deliver(io, &mut output, matched.ticket.sequence()).await?;
                let completed_at = tokio::time::Instant::now();
                ensure!(
                    matched.ticket.publish_wire(),
                    "native response delivery receipt was cancelled"
                );
                let mut state = self.state.lock().await;
                let contracts = state.native.contracts.clone();
                match state
                    .native
                    .core
                    .finish(matched.index, &matched.ticket, || {
                        contracts.commit_comparison(comparison, identity)
                    }) {
                    admission::Finish::Committed(()) => {
                        state.native.publish_delivery(matched.index, self.protocol);
                        let reference =
                            &state.native.core.exchanges[matched.index].native.reference;
                        if self.retain_anchor {
                            self.delivered
                                .lock()
                                .expect("native delivery anchors")
                                .insert(
                                    reference.clone(),
                                    DeliveredAnchor {
                                        started: completed_at,
                                        lane: state.native.core.exchanges[matched.index]
                                            .native
                                            .lane
                                            .clone(),
                                        owner: request::SessionOwner {
                                            scope: state.native.core.exchanges[matched.index]
                                                .source
                                                .source,
                                            case: state.native.core.exchanges[matched.index]
                                                .source
                                                .case_id
                                                .clone(),
                                            epoch: (!matched.run_owned).then_some(matched.epoch),
                                        },
                                    },
                                );
                        }
                        Ok(())
                    }
                    admission::Finish::Failed(error) => Err(error),
                    admission::Finish::Unchanged => {
                        Err(anyhow!("native response did not commit its delivery"))
                    }
                }
            }
            .await;
            if let Err(error) = &result {
                self.reported.store(true, Ordering::Release);
                let mut state = self.state.lock().await;
                if state.finalized_at.is_none() {
                    state.native.core.fail(matched.index, &matched.ticket);
                    state.native.record_failure(
                        self.protocol,
                        &self.endpoint,
                        matched.case.clone(),
                        None,
                        None,
                        &error.to_string(),
                        Default::default(),
                    );
                }
            }
            result
        })
    }
}
