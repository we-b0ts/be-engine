//! HTTP/TLS connection lifetime and delivery.
use super::*;
use crate::dependency::termination::ConnectionControl;
use crate::http::termination::{ClientTermination, ObservedClientIo};

#[derive(Clone)]
struct TerminationTransport {
    control: ConnectionControl,
    observation: ClientTermination,
    delivery: crate::http::termination::DeliveryProgress,
    closed: tokio::sync::watch::Sender<bool>,
    io_finished: tokio::sync::watch::Receiver<bool>,
}

pub(crate) async fn handle_http_replay_connection(
    stream: TcpStream,
    _peer_addr: std::net::SocketAddr,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    ca: Arc<MitmCa>,
) -> Result<()> {
    let control = ConnectionControl::new(&stream)?;
    let termination = ClientTermination::with_connection_control(control.clone());
    match target.protocol {
        ReplayProtocol::Http => serve_http_io(stream, target, state, control, termination).await,
        ReplayProtocol::Https => {
            let server_config = ca.server_config_for_host(&target.host)?;
            let tls = TlsAcceptor::from(server_config)
                .accept(ObservedClientIo::transport(stream, termination.clone()))
                .await
                .with_context(|| {
                    format!("HTTPS replay TLS handshake failed for {}", target.host)
                })?;
            serve_http_io(tls, target, state, control, termination).await
        }
        protocol => Err(anyhow!(
            "HTTP replay received incompatible protocol {protocol:?}"
        )),
    }
}

async fn serve_http_io<T>(
    io: T,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    control: ConnectionControl,
    termination: ClientTermination,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if target.protocol == ReplayProtocol::Http {
        termination.watch_raw_input_after_server_end();
    }
    let mut client_events = termination.subscribe();
    let (closed, mut server_closed) = tokio::sync::watch::channel(false);
    let (io_finished, finished) = tokio::sync::watch::channel(false);
    let transport = TerminationTransport {
        control,
        observation: termination.clone(),
        delivery: termination.delivery(),
        closed,
        io_finished: finished,
    };
    let io = ObservedClientIo::new(io, termination.clone());
    let (deadline_tx, deadline_rx) = tokio::sync::watch::channel(None);
    let pending = Arc::new(std::sync::Mutex::new(None));
    let service_pending = pending.clone();
    let service_state = state.clone();
    let ingress = state.lock().await.protocols.http_ingress.handle();
    let service = service_fn(move |request| {
        // Synchronous service admission precedes any await on Replay state.
        let admission = ingress.admit();
        handle_http_request(
            request,
            target.clone(),
            service_state.clone(),
            service_pending.clone(),
            deadline_tx.clone(),
            transport.clone(),
            admission,
        )
    });
    let result = {
        let providers = state.lock().await.providers.clone();
        let mut session = crate::protocols::http_session(&providers)?;
        let connection = session.connection(io, service, false);
        tokio::pin!(connection);
        let deadline_wait = wait_for_deadline(deadline_rx);
        tokio::pin!(deadline_wait);
        let raw_cancellation = termination.wait_for_cancellation();
        tokio::pin!(raw_cancellation);
        let mut expired = false;
        let mut half_closed = false;
        let mut server_half_close_detail = None;
        loop {
            tokio::select! {
                result = &mut connection => break if half_closed { Ok(()) } else { result.context("failed to serve HTTP replay connection") },
                error = &mut raw_cancellation => break Err(error.into()),
                _ = client_events.changed(), if !expired => {
                    if termination.input_after_server_end()
                        && let Some(detail) = server_half_close_detail.take() {
                        state.lock().await.finish_http_response(detail, Err(anyhow!("Target sent additional HTTP dependency input after recorded server write-half termination")));
                        expired = true;
                        continue;
                    }
                    let observed = pending.lock().expect("HTTP pending termination poisoned")
                        .as_ref().filter(|exchange| !exchange.expected_termination.is_some_and(|end| end.side == crate::dependency::TerminationSide::Server))
                        .and_then(|exchange| exchange.observed_client(&termination));
                    if let Some(observed) = observed {
                        let exchange = pending.lock().expect("HTTP pending termination poisoned").take();
                        if let Some(exchange) = exchange {
                            let completion = exchange.validate_observed(observed, &state).await;
                            let success = completion.is_ok();
                            state.lock().await.finish_http_termination(exchange, completion);
                            if success { half_closed = true; } else { expired = true; }
                        }
                    }
                },
                _ = &mut deadline_wait, if !expired && !half_closed => {
                    expired = true;
                    let exchange = pending.lock().expect("HTTP pending termination poisoned").take();
                    if let Some(exchange) = exchange {
                        state.lock().await.finish_http_termination(exchange, Err(anyhow!("HTTP dependency did not produce its recorded termination within the timing window")));
                    }
                    // A failed assertion is not a transport input. Keep serving
                    // this socket until Target closes or its supervisor ends it.
                },
                _ = server_closed.changed() => {
                    let exchange = pending.lock().expect("HTTP pending termination poisoned").take();
                    if let Some(mut exchange) = exchange {
                        let write_half = exchange.expected_termination.is_some_and(|end| end.scope == crate::dependency::TerminationScope::WriteHalf);
                        let completion = exchange.server_result.take().unwrap_or_else(|| Err("HTTP server termination was not delivered".into())).map_err(|error| anyhow!(error));
                        let success = completion.is_ok();
                        if success && write_half { server_half_close_detail = Some(exchange.detail.clone()); }
                        state.lock().await.finish_http_termination(exchange, completion);
                        if success && write_half { half_closed = true; }
                        else if success { break Ok(()); }
                        else { expired = true; }
                    }
                },
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)), if expired || half_closed => {
                    if state.lock().await.finalized_at.is_some() {
                        break Err(anyhow!("HTTP dependency transport cleaned up after replay finalization"));
                    }
                }
            }
        }
    };
    io_finished.send_replace(true);
    let exchange = pending
        .lock()
        .expect("HTTP pending termination poisoned")
        .take();
    if let Some(mut exchange) = exchange {
        let completion = if exchange
            .expected_termination
            .is_some_and(|end| end.side == crate::dependency::TerminationSide::Server)
        {
            exchange.server_result.take().unwrap_or_else(|| Err("Target terminated HTTP dependency before its recorded server termination was delivered".into())).map_err(|error| anyhow!(error))
        } else {
            match exchange.observed_client(&termination) {
                Some(observed) => exchange.validate_observed(observed, &state).await,
                None => Err(anyhow!(
                    "client did not terminate HTTP dependency connection within recorded timing window"
                )),
            }
        };
        let completed = completion.is_ok();
        state
            .lock()
            .await
            .finish_http_termination(exchange, completion);
        if completed {
            return Ok(());
        }
    }
    result
}

async fn wait_for_deadline(
    mut receiver: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>,
) {
    loop {
        let deadline = *receiver.borrow_and_update();
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline).await;
            return;
        }
        if receiver.changed().await.is_err() {
            pending::<()>().await;
        }
    }
}

async fn handle_http_request(
    request: Request<Incoming>,
    target: ReplayTarget,
    state: Arc<Mutex<ReplayState>>,
    pending_exchange: Arc<std::sync::Mutex<Option<termination::PendingHttpTermination>>>,
    deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
    transport: TerminationTransport,
    mut admission: ingress::Admission,
) -> Result<Response<stream_delivery::DeliveryBody>, Infallible> {
    let started = admission.started();
    let request_started_at = admission.started_at();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let headers = request_headers::capture(request.headers());
    let scheme = match target.protocol {
        ReplayProtocol::Https => HttpReplayScheme::Https,
        _ => HttpReplayScheme::Http,
    };
    let target_key = TargetKey {
        host: target.host,
        port: target.port,
    };
    {
        let state = state.lock().await;
        if state.async_case_quiescing() {
            drop(state);
            transport
                .observation
                .connection_observation()
                .observe_engine_stop();
            let _ = transport.control.reset();
            return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
        }
        state.protocols.http_ingress.configure_head(
            &mut admission,
            scheme,
            &target_key,
            &method,
            &uri,
            host.as_deref(),
        );
    }
    let body = match http_body_util::Limited::new(
        request.into_body(),
        crate::value_limits::MAX_VALUE_BYTES,
    )
    .collect()
    .await
    {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            admission.body_error();
            let state_guard = state.lock().await;
            if state_guard.async_case_quiescing() {
                drop(state_guard);
                transport
                    .observation
                    .connection_observation()
                    .observe_engine_stop();
                let _ = transport.control.reset();
                return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>()
                    .await;
            }
            drop(state_guard);
            return Ok(stream_delivery::ordinary(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("failed to read replay request body: {error}"),
            )));
        }
    };
    let matched = {
        let state_guard = state.lock().await;
        // Body collection can overlap prepare-stop. Close admission under the
        // same lock as request matching so cleanup traffic cannot claim slots.
        if state_guard.async_case_quiescing() {
            admission.complete();
            drop(state_guard);
            transport
                .observation
                .connection_observation()
                .observe_engine_stop();
            let _ = transport.control.reset();
            return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
        }
        drop(state_guard);
        super::admission::select(
            &state,
            contracts::RequestView {
                observation_id: Some(admission.observation_id()),
                scheme,
                target: &target_key,
                method: &method,
                uri: &uri,
                headers: &headers,
                body: &body,
                started_at: request_started_at,
            },
            host.as_deref(),
            &mut admission,
        )
        .await
    };
    if let Err(error) =
        crate::replay::policy::request_contract::hypotheses::await_durable(&state).await
    {
        state.lock().await.record_unmatched_http(
            scheme,
            &target_key,
            &method,
            &uri,
            "hypothesis evidence persistence failed".into(),
        );
        let _ = transport.control.reset();
        tracing::warn!(error=%error, "HTTP hypothesis evidence could not be persisted before delivery");
        return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
    }
    let output_index = match &matched {
        Ok(record) => record.stream_delivery.as_ref().map(|detail| detail.index),
        Err(
            HttpReplayMatchError::ClientTerminated(exchange)
            | HttpReplayMatchError::ServerTerminated(exchange),
        ) => Some(exchange.detail.index),
        _ => None,
    };
    if let Some(index) = output_index
        && let Err(error) = super::admission::wait_output(&state, index).await
    {
        tracing::warn!(%error, "HTTP output sequence wait failed");
        let _ = transport.control.reset();
        return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
    }
    let record = match matched {
        Ok(record) => record,
        Err(HttpReplayMatchError::ClientTerminated(mut exchange)) => {
            exchange.started = started;
            if exchange.lifecycle_stop.is_none() {
                deadline.send_replace(Some(exchange.timing.termination_deadline(exchange.started)));
            }
            *pending_exchange
                .lock()
                .expect("HTTP pending termination poisoned") = Some(*exchange);
            return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
        }
        Err(HttpReplayMatchError::ServerTerminated(mut exchange)) => {
            exchange.started = started;
            exchange.timing = exchange.timing.for_replay(
                state.lock().await.stream_timing == Some(crate::replay::ReplayStreamTiming::Fast),
            );
            let end = exchange
                .expected_termination
                .expect("recorded server termination");
            let delivery_at = exchange.timing.response_deadline(started);
            let cleanup_at = exchange.timing.termination_deadline(started);
            deadline.send_replace(Some(cleanup_at));
            *pending_exchange
                .lock()
                .expect("HTTP pending termination poisoned") = Some(*exchange);
            let close = termination::ServerClose::new(
                transport.control,
                transport.observation,
                pending_exchange,
                transport.closed,
                end,
                cleanup_at,
            );
            tokio::time::sleep_until(delivery_at).await;
            close.finish();
            return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
        }
        Err(HttpReplayMatchError::Blackhole) => {
            return pending::<Result<Response<stream_delivery::DeliveryBody>, Infallible>>().await;
        }
        Err(HttpReplayMatchError::BadGateway(reason)) => {
            return Ok(stream_delivery::ordinary(error_response(
                StatusCode::BAD_GATEWAY,
                &reason,
            )));
        }
    };
    let sequence_claim = if let Some(index) = output_index {
        state
            .lock()
            .await
            .protocols
            .http_sequence_claims
            .get(&index)
            .cloned()
    } else {
        None
    };
    let sequence_progress = transport.delivery.clone();
    let mut record = record;
    let ordinary_delivery = stream_delivery::full_delivery::Transport {
        observation: Some(transport.observation.clone()),
        progress: transport.delivery.clone(),
        finished: transport.io_finished.clone(),
    };
    let mut server_close = None;
    let client_prefix = if record.lifecycle_stop.is_some()
        || record.outcome.is_client_terminated()
        || record.outcome.is_server_terminated()
    {
        let delivered = Arc::new(crate::http::termination::PrefixDelivery::new(
            transport.delivery,
        ));
        let detail = record
            .stream_delivery
            .take()
            .expect("matched cancelled stream delivery");
        let mut exchange = if let Some(gate) = record.lifecycle_stop.clone() {
            termination::PendingHttpTermination::for_lifecycle_stop(detail, &record, gate)
        } else {
            termination::PendingHttpTermination::new(detail, &record)
        };
        exchange.started = started;
        exchange.timing = exchange.timing.for_replay(
            state.lock().await.stream_timing == Some(crate::replay::ReplayStreamTiming::Fast),
        );
        exchange.prefix_delivered = Some(delivered.clone());
        if record.lifecycle_stop.is_some() {
            state.lock().await.protocols.http_exchanges[exchange.detail.index].lifecycle_prefix =
                Some(delivered.clone());
        }
        if record.lifecycle_stop.is_none() && record.outcome.is_server_terminated() {
            server_close = Some(termination::ServerClose::new(
                transport.control,
                transport.observation,
                pending_exchange.clone(),
                transport.closed,
                record.outcome.termination().expect("server termination"),
                exchange.timing.termination_deadline(started),
            ));
        }
        if record.lifecycle_stop.is_none() {
            deadline.send_replace(Some(exchange.timing.termination_deadline(started)));
        }
        *pending_exchange
            .lock()
            .expect("HTTP pending termination poisoned") = Some(exchange);
        Some(delivered)
    } else {
        None
    };
    let response = stream_delivery::response(
        record,
        started,
        state,
        client_prefix,
        server_close,
        ordinary_delivery,
    )
    .await
    .unwrap_or_else(|error| {
        stream_delivery::ordinary(error_response(StatusCode::BAD_GATEWAY, &error.to_string()))
    });
    Ok(crate::http::wire_events::replay(
        response,
        sequence_claim,
        sequence_progress,
    ))
}
