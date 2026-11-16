//! Native drivers submit requests while the host owns matching and actual delivery.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use traffic_protocol::{
    connection::{
        ConnectionInfo, ConnectionIo, NativeFuture, RequestHost, ResponseDelivery, ResponseFramer,
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
    let host = Arc::new(Host {
        state,
        protocol,
        endpoint,
        reported: Arc::new(AtomicBool::new(false)),
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
            );
        }
    }
    result
}

struct Host<P: ReplayProtocolSet> {
    state: Arc<Mutex<RuntimeState<P>>>,
    protocol: ProtocolId,
    endpoint: Endpoint,
    reported: Arc<AtomicBool>,
}

impl<P: ReplayProtocolSet> RequestHost for Host<P> {
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
        Box::pin(async move {
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
            let mut request = request::Request {
                protocol: self.protocol,
                endpoint: self.endpoint.clone(),
                message,
                observed,
                bytes,
            };
            let matched = admission::request::execute(
                &self.state,
                &mut request,
                tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .await;
            let matched = match matched {
                Ok(matched) => matched,
                Err(error) => {
                    self.reported.store(true, Ordering::Release);
                    return Err(error.into());
                }
            };
            let guard = matched.ticket.guard();
            Ok(Box::new(Delivery {
                matched,
                started,
                state: self.state.clone(),
                protocol: self.protocol,
                endpoint: self.endpoint.clone(),
                reported: self.reported.clone(),
                _guard: guard,
            }) as Box<dyn ResponseDelivery>)
        })
    }
}

struct Delivery<P: ReplayProtocolSet> {
    matched: request::Matched,
    started: tokio::time::Instant,
    state: Arc<Mutex<RuntimeState<P>>>,
    protocol: ProtocolId,
    endpoint: Endpoint,
    reported: Arc<AtomicBool>,
    _guard: admission::DeliveryGuard,
}

impl<P: ReplayProtocolSet> ResponseDelivery for Delivery<P> {
    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn ConnectionIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let matched = &self.matched;
            let result = async {
                matched.ticket.wait_sequence_delivery().await?;
                let fast = self.state.lock().await.stream_timing == Some(ReplayStreamTiming::Fast);
                super::super::exchange::ReplayExchangeTiming::from_duration(
                    matched.delay,
                    crate::DependencyExchangeOutcome::Response,
                )
                .delay_response_from_request(self.started, fast)
                .await;
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
                    state
                        .native
                        .render_response(matched.index, matched.observed)?
                };
                let response = framer.prepare_output(response)?;
                let mut output = traffic_protocol::output::FramedOutput::new(response, framer);
                traffic_replay::output::deliver(io, &mut output, matched.ticket.sequence()).await?;
                ensure!(
                    matched.ticket.publish_wire(),
                    "native response delivery receipt was cancelled"
                );
                let mut state = self.state.lock().await;
                match state
                    .native
                    .core
                    .finish(matched.index, &matched.ticket, || Ok(()))
                {
                    admission::Finish::Committed(()) => {
                        state.native.refresh_global_report(matched.index);
                        *state
                            .native
                            .matched
                            .entry(self.protocol.as_str().into())
                            .or_default() += 1;
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
                    );
                }
            }
            result
        })
    }
}
