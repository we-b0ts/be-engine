//! Fresh sessions share one scheduler; completion uses only actual Target traffic.
mod heartbeat;
mod namespace;
mod transport;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use std::collections::BTreeMap;
use tokio::time::{Duration, Instant, sleep_until};

use super::timing::{Advance, cancellation, delivery_prefix, transport_cancellation};
use super::{Feedback, HttpClient, NativeEvent, ReplayResponse, elapsed_ms};
use crate::interaction::{
    lifecycle::LifecycleDecision,
    model::{
        ClientTransportEnd, EndReason, InputAction, InputActionKind, InputTranscript, Protocol,
        WireMessage,
    },
    observation::Observation,
    socketio::{EngineIoPacket, SocketIoDecoder, SocketIoKind, native_receipts},
};
use transport::{ReaderEvent, Transport};

pub(super) async fn execute_with_feedback(
    client: &HttpClient,
    origin: &str,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
    feedback: Feedback,
) -> Result<ReplayResponse> {
    let Feedback {
        mut dependency_failure,
        native_events,
        input_timing,
    } = feedback;
    transcript.validate()?;
    let started = Instant::now();
    let started_at = chrono::Utc::now();
    let mut observed = Observation::new(transcript.protocol, transcript.policy.clone())?;
    let budget = header_timeout
        .min(Duration::from_millis(transcript.policy.request_timeout_ms))
        .min(Duration::from_millis(transcript.policy.max_duration_ms));
    let connect = tokio::time::timeout(
        budget,
        Transport::connect(
            client.clone(),
            origin,
            request,
            transcript.policy.max_message_bytes,
            transcript.protocol == Protocol::WebSocket,
        ),
    );
    let mut transport = tokio::select! {
        biased;
        _=crate::dependency::execution::rejected(&mut dependency_failure)=>return Err(crate::dependency::execution::UnmatchedDependency {observed_status:None}.into()),
        transport=connect=>transport.context("Target session handshake timed out")??,
    };
    let mut server_decoder = SocketIoDecoder::new(transcript.policy.max_message_bytes);
    let mut completed = BTreeMap::new();
    let mut next = 0;
    let mut last_offset = 0;
    let mut last_sent = started;
    let mut server_ordinals: BTreeMap<String, u64> = BTreeMap::new();
    let mut server_acks = BTreeMap::new();
    let mut native_receipts = native_receipts::Receipts::default();
    let mut timing_wait: Option<futures_util::future::BoxFuture<'static, Result<Advance>>> = None;
    let mut timing_sequence = None;
    let mut timing_ready = None;
    let mut removed_ms = 0;
    let ordered_fast = input_timing
        .as_ref()
        .is_some_and(|timing| timing.ordered_fast());
    let fast_tail = input_timing.as_ref().and_then(|timing| timing.fast_tail());
    let heartbeat_acks = fast_tail
        .as_ref()
        .and_then(|tail| tail.heartbeat_acks.as_ref());
    let mut tail_wait: Option<futures_util::future::BoxFuture<'static, Result<Advance>>> = None;
    let mut tail_ready_at: Option<Instant> = None;
    let mut tail_compressed = false;
    let mut output_count = 0;
    let mut last_output = started;
    let mut heartbeats = heartbeat::Heartbeats::new(transcript);
    let mut namespaces = namespace::Admission::default();
    let has_transport_end = transcript
        .actions
        .last()
        .is_some_and(|action| matches!(action.action, InputActionKind::TransportEnd { .. }));
    let (mut reason, mut transport_clean) = 'session: loop {
        if dependency_failure
            .as_ref()
            .is_some_and(|failure| *failure.borrow())
        {
            break (EndReason::DependencyFailure, false);
        }
        // Protocol controls are evidence, not replay input timers. Target heartbeat
        // replies are generated independently when its own live ping arrives.
        while let Some(action) = transcript.actions.get(next) {
            let InputActionKind::Message { message } = &action.action else {
                break;
            };
            if !is_control(
                transcript.protocol,
                message,
                transcript.policy.max_message_bytes,
            )? {
                break;
            }
            if heartbeats.literal_pong(action, message, transcript.policy.max_message_bytes)? {
                break;
            }
            let before = observed.pending();
            let actual = observed.input(message.clone(), elapsed_ms(started))?;
            note_completed(before, &observed, &mut completed);
            ensure!(
                actual.sequence == action.sequence,
                "recorded session control identity is inconsistent"
            );
            next += 1;
        }
        let now = elapsed_ms(started);
        match observed.decision(now) {
            LifecycleDecision::Close(EndReason::BusinessIdle)
                if (transcript.protocol == Protocol::SocketIo || has_transport_end)
                    && next < transcript.actions.len() => {}
            LifecycleDecision::Close(reason) => break (reason, true),
            LifecycleDecision::Fail(reason) => break (reason, false),
            _ => {}
        }
        let action = transcript.actions.get(next);
        let namespace_ready = transcript.protocol != Protocol::SocketIo
            || action.is_none_or(|action| {
                namespaces.permits(action, transcript.policy.max_message_bytes)
            });
        let admitted = action
            .filter(|_| namespace_ready)
            .filter(|action| {
                transcript.protocol != Protocol::SocketIo
                    || action.after.iter().all(|id| completed.contains_key(id))
            })
            .filter(|action| {
                action.ack_ref.as_ref().is_none_or(|reference| {
                    server_acks.contains_key(&(
                        reference.namespace.clone(),
                        reference.server_event_ordinal,
                    ))
                })
            });
        let at_fast_tail = fast_tail.as_ref().is_some_and(|tail| {
            let ready = if let Some(required) = heartbeat_acks {
                transport.is_websocket()
                    && output_count == tail.output_count
                    && heartbeats.complete(true)
                    && required.is_subset(&native_receipts.acknowledged)
                    && observed
                        .pending()
                        .iter()
                        .all(|id| native_receipts.acknowledged.contains(id))
            } else {
                output_count >= tail.output_count && observed.pending().is_empty()
            };
            ready
                && match tail.close_sequence {
                    Some(sequence) => admitted.is_some_and(|action| action.sequence == sequence),
                    None => action.is_none(),
                }
        });
        if at_fast_tail
            && tail_wait.is_none()
            && tail_ready_at.is_none()
            && let Some(timing) = &input_timing
        {
            let timing = timing.clone();
            tail_wait = Some(Box::pin(async move { timing.wait_fast_tail().await }));
        }
        let fast_idle_due = fast_tail
            .as_ref()
            .filter(|tail| at_fast_tail && tail.close_sequence.is_none())
            .zip(tail_ready_at)
            .map(|(tail, ready)| {
                ready.max(last_sent).max(last_output) + Duration::from_millis(tail.idle_ms)
            });
        if let (Some(action), Some(timing)) = (admitted, &input_timing)
            && (action.compressible_gap || delivery_prefix(action))
            && !cancellation(action)
            && timing_sequence != Some(action.sequence)
        {
            let timing = timing.clone();
            let sequence = action.sequence;
            let completed = action.after.clone();
            timing_sequence = Some(sequence);
            timing_wait = Some(Box::pin(
                async move { timing.wait(sequence, completed).await },
            ));
        }
        let due = admitted.and_then(|action| {
            if matches!(action.action, InputActionKind::TransportEnd { .. }) {
                return Some(
                    started + Duration::from_millis(action.offset_ms.saturating_sub(removed_ms)),
                );
            }
            if transcript.protocol == Protocol::SocketIo {
                if input_timing.is_some()
                    && (action.compressible_gap || delivery_prefix(action))
                    && !cancellation(action)
                {
                    return (timing_ready == Some(action.sequence)).then(Instant::now);
                }
                // Without dependency coverage no gap is eligible for acceleration.
                let removed = if tail_ready_at.is_none()
                    && fast_tail
                        .as_ref()
                        .is_some_and(|tail| tail.close_sequence == Some(action.sequence))
                {
                    0
                } else {
                    removed_ms
                };
                let mut due =
                    started + Duration::from_millis(action.offset_ms.saturating_sub(removed));
                if cancellation(action)
                    && !tail_compressed
                    && let Some(gap_start) = action.gap_start_ms
                    && let Some(barrier) =
                        action.after.iter().filter_map(|id| completed.get(id)).max()
                {
                    // A Source completion-bound close differs from independent
                    // cancellation. Preserve its full post-completion interval.
                    due = due.max(
                        *barrier
                            + Duration::from_millis(action.offset_ms.saturating_sub(gap_start)),
                    );
                }
                return Some(due);
            }
            websocket_action_due(
                action,
                &completed,
                last_offset,
                last_sent,
                transcript.policy.input_gap_ms,
            )
        });
        let lifecycle_deadline = session_deadline(transcript, &observed, next, started);
        // A recorded transport cancellation must remain available while an
        // earlier input is waiting for an ACK, namespace or dependency delivery.
        let cancel = transcript.actions.iter().skip(next + 1).find(|action| {
            transport_cancellation(action)
                && (transcript.protocol == Protocol::SocketIo
                    || matches!(action.action, InputActionKind::TransportEnd { .. }))
        });
        let cancel_due = cancel.map(|action| {
            let removed = if ordered_fast { 0 } else { removed_ms };
            started + Duration::from_millis(action.offset_ms.saturating_sub(removed))
        });
        let wake = due
            .into_iter()
            .chain(fast_idle_due)
            .fold(lifecycle_deadline, Instant::min);
        let heartbeat_due = heartbeats.next_due();
        tokio::select! {
            biased;
            _ = async { match dependency_failure.as_mut() {
                Some(failure) => {let _=failure.changed().await;},
                None => std::future::pending::<()>().await,
            } } => {
                if dependency_failure.as_ref().is_some_and(|failure|*failure.borrow()) {break (EndReason::DependencyFailure,false);}
                dependency_failure=None;
            }
            _ = sleep_until(cancel_due.unwrap_or(lifecycle_deadline)), if cancel_due.is_some_and(|cancel| due.is_none_or(|due| due > cancel)) => {
                let action = cancel.expect("cancellation deadline");
                let deadline = Instant::now() + Duration::from_millis(transcript.policy.cleanup_timeout_ms);
                match &action.action {
                    InputActionKind::Close {code, reason} => {
                        observed.client_close(*code, reason.clone(), elapsed_ms(started))?;
                        tokio::time::timeout_at(deadline, transport.close(*code, reason)).await.context("Target cancellation timed out")??;
                    }
                    InputActionKind::Message {message} => {
                        observed.input(message.clone(), elapsed_ms(started))?;
                        tokio::time::timeout_at(deadline, transport.send(message)).await.context("Target cancellation timed out")??;
                    }
                    InputActionKind::TransportEnd { end } => {
                        // Skipped earlier input stays incomplete even though
                        // the independent physical cancellation still occurs.
                        break terminate_transport(&mut transport, &mut TerminalObservation {
                            observed: &mut observed, server_decoder: &mut server_decoder,
                            native_events: &native_events, server_ordinals: &mut server_ordinals,
                            native_receipts: &mut native_receipts,
                        }, *end, started,
                            transcript.policy.cleanup_timeout_ms, &mut dependency_failure).await?;
                    }
                    _ => unreachable!("transport cancellation"),
                }
                // Keep next unchanged: skipped inputs make execution incomplete.
                break (EndReason::ClientClose, true);
            }
            result = async { timing_wait.as_mut().expect("pending timing query").await }, if timing_wait.is_some() => {
                let advance = result?;
                removed_ms = advance.removed_ms;
                timing_ready = timing_sequence;
                timing_wait = None;
            }
            result = async { tail_wait.as_mut().expect("pending fast tail query").await }, if tail_wait.is_some() => {
                let advance = result?;
                tail_compressed = advance.removed_ms > removed_ms;
                removed_ms = advance.removed_ms;
                tail_ready_at = Some(Instant::now());
                tail_wait = None;
            }
            incoming = transport.recv() => {
                match incoming.context("Target session reader stopped")? {
                    ReaderEvent::Message(message) => {
                        let before = observed.pending();
                        if !observed.output(message.clone(), elapsed_ms(started))?.heartbeat {
                            output_count += 1;
                            last_output = Instant::now();
                        }
                        note_completed(before, &observed, &mut completed);
                        if transcript.protocol == Protocol::SocketIo {
                            for packet in server_decoder.push(&message)? {
                                match packet {
                                    EngineIoPacket::Open(open) => transport.set_sid(open.sid)?,
                                    EngineIoPacket::Message(packet) if packet.kind == SocketIoKind::Connect => {
                                        namespaces.accept(&packet.namespace);
                                        if let Some(sink) = &native_events {
                                            tokio::select! {
                                                biased;
                                                _ = crate::dependency::execution::rejected(&mut dependency_failure) => break 'session (EndReason::DependencyFailure, false),
                                                result = tokio::time::timeout_at(lifecycle_deadline, sink.connected(&packet.namespace, packet.data.as_ref().and_then(|data| data.get("sid")).and_then(serde_json::Value::as_str))) => {
                                                    result.context("native namespace observation timed out")??;
                                                }
                                            }
                                        }
                                    }
                                    EngineIoPacket::Ping(payload) => {
                                        if heartbeats.ping(payload.clone(), Instant::now())? {
                                            tokio::time::timeout_at(lifecycle_deadline,
                                                transport.send(&WireMessage::text(format!("3{payload}"))))
                                                .await.context("Engine.IO heartbeat send timed out")??;
                                        }
                                    }
                                    EngineIoPacket::Message(packet) if matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck) => {
                                        if let Some(sequence) = native_receipts.acknowledge(&packet) && let Some(sink) = &native_events {
                                            sink.acknowledged(sequence).await?;
                                        }
                                    }
                                    EngineIoPacket::Message(packet) if matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent) => {
                                        let ordinal = server_ordinals.entry(packet.namespace.clone()).or_default();
                                        *ordinal = ordinal.checked_add(1).context("native event ordinal exceeds range")?;
                                        if let (Some(sink), Some(event)) = (&native_events, packet.event_name()) {
                                            let event = NativeEvent { namespace: packet.namespace.clone(), event: event.into(), ordinal: *ordinal };
                                            tokio::select! {
                                                biased;
                                                _ = crate::dependency::execution::rejected(&mut dependency_failure) => break 'session (EndReason::DependencyFailure, false),
                                                result = tokio::time::timeout_at(lifecycle_deadline, sink.observe(event)) => {
                                                    result.context("native event observation timed out")??;
                                                }
                                            }
                                        }
                                        if let Some(id) = packet.id { server_acks.insert((packet.namespace, *ordinal), id); }
                                    }
                                    EngineIoPacket::Close if !transport.is_websocket() => break 'session (EndReason::ServerEof, true),
                                    _ => {}
                                }
                            }
                        }
                    }
                    ReaderEvent::Ping(bytes) => {
                        tokio::time::timeout_at(lifecycle_deadline, transport.pong(bytes))
                            .await.context("WebSocket heartbeat send timed out")??;
                    }
                    ReaderEvent::Closed => break (EndReason::ServerEof, true),
                    ReaderEvent::Close { code, reason } => {
                        observed.server_close(code, reason);
                        break (EndReason::ServerEof, true);
                    }
                    ReaderEvent::Error(message) => anyhow::bail!("Target session transport failed: {message}"),
                }
            }
            _ = sleep_until(heartbeat_due.unwrap_or(lifecycle_deadline)), if heartbeat_due.is_some() => {
                let message = heartbeats.take_due();
                tokio::time::timeout_at(lifecycle_deadline, transport.send(&message))
                    .await.context("recorded Engine.IO heartbeat send timed out")??;
            }
            _ = sleep_until(wake) => {
                if fast_idle_due.is_some_and(|due| Instant::now() >= due) {
                    let reason = if heartbeat_acks.is_some() {
                        EndReason::FastHeartbeatTailSkipped
                    } else {
                        EndReason::BusinessIdle
                    };
                    break (reason, true);
                }
                let Some(action) = action.filter(|_| due.is_some_and(|due| Instant::now() >= due)) else { continue; };
                match &action.action {
                    InputActionKind::Message { message } => {
                        let message = if transcript.protocol == Protocol::SocketIo { rebind_ack(message, action, &server_acks)? } else { message.clone() };
                        let actual_action = observed.input(message.clone(), elapsed_ms(started))?;
                        ensure!(actual_action.sequence == action.sequence, "recorded session input identity is inconsistent; re-record this case");
                        if transcript.protocol == Protocol::SocketIo {
                            namespaces.sent(&message, transcript.policy.max_message_bytes)?;
                        }
                        // Source heartbeats never drive the Target heartbeat clock.
                        let control = transcript.protocol == Protocol::SocketIo
                            && message.kind == crate::interaction::model::MessageKind::Text
                            && crate::interaction::socketio::decode_engine_io_text(&message.data, transcript.policy.max_message_bytes)?.is_heartbeat();
                        if !control || heartbeats.recorded_pong(&message, transcript.policy.max_message_bytes)? {
                            tokio::time::timeout_at(started + Duration::from_millis(observed.next_deadline_ms()),
                                transport.send(&message)).await.context("Target session input send timed out")??;
                            if (native_events.is_some() || heartbeat_acks.is_some()) && transcript.protocol == Protocol::SocketIo {
                                native_receipts.sent(action.sequence, &message, transcript.policy.max_message_bytes)?;
                            }
                        }
                        if transcript.protocol == Protocol::SocketIo
                            && message.kind == crate::interaction::model::MessageKind::Text
                            && message.data == "1"
                        {
                            next += 1;
                            break (EndReason::ClientClose, true);
                        }
                    }
                    InputActionKind::Upgrade { uri, headers } => {
                        observed.upgrade(uri.clone(), headers.clone(), elapsed_ms(started))?;
                        tokio::time::timeout_at(started + Duration::from_millis(observed.next_deadline_ms()),
                            transport.upgrade(uri, headers)).await.context("Engine.IO upgrade timed out")??;
                    },
                    InputActionKind::Close { code, reason } => {
                        let actual = observed.client_close(*code, reason.clone(), elapsed_ms(started))?;
                        ensure!(actual.sequence == action.sequence, "recorded session close identity is inconsistent");
                        let close_deadline = Instant::now() + Duration::from_millis(transcript.policy.cleanup_timeout_ms);
                        tokio::select! {
                            biased;
                            _ = crate::dependency::execution::rejected(&mut dependency_failure) => {
                                break 'session (EndReason::DependencyFailure, false);
                            }
                            result = tokio::time::timeout_at(close_deadline, transport.close(*code, reason)) => {
                                result.context("Target session close timed out")??;
                            }
                        }
                        next += 1;
                        break (EndReason::ClientClose, true);
                    }
                    InputActionKind::TransportEnd { end } => {
                        let ended = terminate_transport(&mut transport, &mut TerminalObservation {
                            observed: &mut observed, server_decoder: &mut server_decoder,
                            native_events: &native_events, server_ordinals: &mut server_ordinals,
                            native_receipts: &mut native_receipts,
                        }, *end, started,
                            transcript.policy.cleanup_timeout_ms, &mut dependency_failure).await?;
                        next += 1;
                        break ended;
                    }
                }
                next += 1;
                last_offset = action.offset_ms;
                last_sent = Instant::now();
            }
        }
    };
    let cleanup = Duration::from_millis(transcript.policy.cleanup_timeout_ms);
    // A skipped heartbeat tail releases the transport by dropping it, without
    // the protocol CLOSE frames normally sent by the cleanup path.
    let mut closed = matches!(
        reason,
        EndReason::ServerEof | EndReason::FastHeartbeatTailSkipped
    ) || transport.raw_end_complete();
    if !closed && transport_clean {
        tokio::select! {
            biased;
            _ = crate::dependency::execution::rejected(&mut dependency_failure) => {
                reason = EndReason::DependencyFailure;
                transport_clean = false;
            }
            result = tokio::time::timeout(cleanup, transport.close(Some(1000), "recording case complete")) => {
                match result {
                    Ok(Ok(())) => closed = true,
                    Ok(Err(_)) => { reason = EndReason::TransportError; transport_clean = false; }
                    Err(_) => { reason = EndReason::CleanupTimeout; transport_clean = false; }
                }
            }
        }
    }
    if !closed {
        let _ = tokio::time::timeout(
            cleanup,
            transport.abort(Some(1000), "recording case complete"),
        )
        .await;
    }
    let (actual_input, observation) = observed.finish(
        reason,
        elapsed_ms(started),
        transport_clean
            && closed
            && next == transcript.actions.len()
            && heartbeats.complete(
                reason == EndReason::FastHeartbeatTailSkipped
                    || removed_ms > 0
                        && matches!(
                            reason,
                            EndReason::ClientClose | EndReason::ClientTransportEnd
                        ),
            ),
    )?;
    if reason == EndReason::ClientTransportEnd && next == transcript.actions.len() {
        ensure!(
            actual_input.actions.last().map(|action| action.sequence)
                == transcript.actions.last().map(|action| action.sequence),
            "recorded session transport-end identity is inconsistent"
        );
    }
    Ok(ReplayResponse {
        started_at,
        completed_at: chrono::Utc::now(),
        status: transport.status,
        headers: transport.headers.clone(),
        body: Bytes::new(),
        observation,
    })
}

async fn terminate_transport(
    transport: &mut Transport,
    observation: &mut TerminalObservation<'_>,
    end: ClientTransportEnd,
    started: Instant,
    cleanup_ms: u64,
    dependency_failure: &mut Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(EndReason, bool)> {
    ensure!(
        transport.is_websocket(),
        "client transport end requires an active WebSocket"
    );
    let dispatched_at = transport.begin_transport_end(end)?;
    let completion = async {
        loop {
            let actual = transport
                .recv_observation()
                .await
                .context("Target reader stopped before physical termination")?;
            if actual.at <= dispatched_at {
                match actual.event {
                    ReaderEvent::Message(message) => {
                        let offset = actual
                            .at
                            .saturating_duration_since(started.into_std())
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX);
                        observation.output_before_end(message, offset).await?;
                    }
                    ReaderEvent::Ping(_) => {}
                    ReaderEvent::Close { .. } | ReaderEvent::Closed => {
                        anyhow::bail!("Target ended before recorded client transport input")
                    }
                    ReaderEvent::Error(_) => anyhow::bail!(
                        "Target transport failed before recorded client transport input"
                    ),
                }
                continue;
            }
            match actual.event {
                ReaderEvent::Message(_) | ReaderEvent::Ping(_) | ReaderEvent::Close { .. } => {}
                ReaderEvent::Closed => break,
                ReaderEvent::Error(_) => anyhow::bail!("Target transport termination failed"),
            }
        }
        let offset = dispatched_at
            .saturating_duration_since(started.into_std())
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        observation.observed.client_transport_end(end, offset)?;
        transport.complete_transport_end();
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::select! {
        biased;
        _ = crate::dependency::execution::rejected(dependency_failure) => {
            return Ok((EndReason::DependencyFailure, false));
        }
        result = tokio::time::timeout(Duration::from_millis(cleanup_ms), completion) => result,
    };
    match result {
        Ok(Ok(())) => Ok((EndReason::ClientTransportEnd, true)),
        Ok(Err(error)) => Err(error.context("Target client transport end failed")),
        Err(_) => Ok((EndReason::CleanupTimeout, false)),
    }
}

/// The reader may already have queued output when the independent cancellation
/// deadline fires. Retain those facts and native receipts before ending input.
struct TerminalObservation<'a> {
    observed: &'a mut Observation,
    server_decoder: &'a mut SocketIoDecoder,
    native_events: &'a Option<std::sync::Arc<dyn super::NativeEventSink>>,
    server_ordinals: &'a mut BTreeMap<String, u64>,
    native_receipts: &'a mut native_receipts::Receipts,
}

impl TerminalObservation<'_> {
    async fn output_before_end(&mut self, message: WireMessage, offset: u64) -> Result<()> {
        self.observed.output(message.clone(), offset)?;
        if self.observed.protocol() != Protocol::SocketIo {
            return Ok(());
        }
        for packet in self.server_decoder.push(&message)? {
            match packet {
                EngineIoPacket::Close => {
                    anyhow::bail!("Target Engine.IO CLOSE preceded client transport input")
                }
                EngineIoPacket::Message(packet) if packet.kind == SocketIoKind::Connect => {
                    if let Some(sink) = self.native_events {
                        sink.connected(
                            &packet.namespace,
                            packet
                                .data
                                .as_ref()
                                .and_then(|data| data.get("sid"))
                                .and_then(serde_json::Value::as_str),
                        )
                        .await?;
                    }
                }
                EngineIoPacket::Message(packet)
                    if matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck) =>
                {
                    if let Some(sequence) = self.native_receipts.acknowledge(&packet)
                        && let Some(sink) = self.native_events
                    {
                        sink.acknowledged(sequence).await?;
                    }
                }
                EngineIoPacket::Message(packet)
                    if matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent) =>
                {
                    let ordinal = self
                        .server_ordinals
                        .entry(packet.namespace.clone())
                        .or_default();
                    *ordinal = ordinal
                        .checked_add(1)
                        .context("native event ordinal exceeds range")?;
                    if let (Some(sink), Some(event)) = (self.native_events, packet.event_name()) {
                        sink.observe(NativeEvent {
                            namespace: packet.namespace.clone(),
                            event: event.into(),
                            ordinal: *ordinal,
                        })
                        .await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
async fn execute(
    client: &HttpClient,
    origin: &str,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
) -> Result<ReplayResponse> {
    execute_with_feedback(
        client,
        origin,
        request,
        transcript,
        header_timeout,
        Feedback::default(),
    )
    .await
}

fn is_control(protocol: Protocol, message: &WireMessage, limit: usize) -> Result<bool> {
    Ok(protocol == Protocol::SocketIo
        && message.kind == crate::interaction::model::MessageKind::Text
        && crate::interaction::socketio::decode_engine_io_text(&message.data, limit)?
            .is_heartbeat())
}

fn note_completed(
    before: Vec<u64>,
    observed: &Observation,
    completed: &mut BTreeMap<u64, Instant>,
) {
    let pending = observed.pending();
    for id in before {
        if !pending.contains(&id) {
            completed.insert(id, Instant::now());
        }
    }
}

fn session_deadline(
    transcript: &InputTranscript,
    observed: &Observation,
    next: usize,
    started: Instant,
) -> Instant {
    let terminal_transport = transcript
        .actions
        .last()
        .is_some_and(|action| matches!(action.action, InputActionKind::TransportEnd { .. }));
    let millis = if (transcript.protocol == Protocol::SocketIo || terminal_transport)
        && next < transcript.actions.len()
        && observed.pending().is_empty()
    {
        // Header timeout bounds only Transport::connect. Future recorded input
        // owns the session until its policy budget, not the HTTP handshake cap.
        transcript.policy.max_duration_ms
    } else {
        observed.next_deadline_ms()
    };
    started + Duration::from_millis(millis)
}

fn websocket_action_due(
    action: &InputAction,
    completed: &BTreeMap<u64, Instant>,
    last_offset: u64,
    last_sent: Instant,
    input_gap_ms: u64,
) -> Option<Instant> {
    let mut barrier = None;
    for sequence in &action.after {
        let at = *completed.get(sequence)?;
        barrier = Some(barrier.map_or(at, |previous: Instant| previous.max(at)));
    }
    let closes = matches!(
        action.action,
        InputActionKind::Close { .. } | InputActionKind::TransportEnd { .. }
    );
    if closes && let Some(gap_start) = action.gap_start_ms {
        let delay = action.offset_ms.checked_sub(gap_start)?;
        // Keep the actual completion barrier even when client idle time is compressed.
        return barrier?.checked_add(Duration::from_millis(delay));
    }
    if action.compressible_gap {
        let gap_start = action.gap_start_ms?;
        let delay = action.offset_ms.saturating_sub(gap_start).min(input_gap_ms);
        Some(barrier? + Duration::from_millis(delay))
    } else {
        let due = last_sent + Duration::from_millis(action.offset_ms.saturating_sub(last_offset));
        Some(barrier.map_or(due, |barrier| due.max(barrier)))
    }
}

fn rebind_ack(
    message: &WireMessage,
    action: &InputAction,
    server_acks: &BTreeMap<(String, u64), u64>,
) -> Result<WireMessage> {
    let Some(reference) = &action.ack_ref else {
        if message.kind == crate::interaction::model::MessageKind::Text
            && let EngineIoPacket::Message(packet) =
                crate::interaction::socketio::decode_engine_io_text(&message.data, usize::MAX)?
        {
            ensure!(
                !matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck),
                "recorded client ACK lacks a Target event binding; re-record this case"
            );
        }
        return Ok(message.clone());
    };
    let id = server_acks
        .get(&(reference.namespace.clone(), reference.server_event_ordinal))
        .context("recorded client ACK has no corresponding actual Target server event")?;
    let mut packet =
        crate::interaction::socketio::decode_engine_io_text(&message.data, usize::MAX)?;
    let EngineIoPacket::Message(ref mut packet) = packet else {
        anyhow::bail!("ACK reference is not a Socket.IO packet");
    };
    ensure!(
        matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck),
        "ACK reference requires a client ACK packet"
    );
    ensure!(
        packet.namespace == reference.namespace,
        "recorded client ACK namespace disagrees with its Target event binding"
    );
    packet.id = Some(*id);
    Ok(WireMessage::text(packet.encode_engine_io()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::model::InputActionKind;

    #[test]
    fn future_recorded_input_uses_session_budget_then_restores_business_idle() {
        let started = Instant::now();
        let mut input = InputTranscript::new(
            Protocol::SocketIo,
            crate::interaction::policy::InteractionPolicy::default(),
        );
        input.actions.push(InputAction {
            sequence: 1,
            offset_ms: 40_000,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text("1"),
            },
        });
        let mut observed = Observation::new(input.protocol, input.policy.clone()).unwrap();
        observed.output(WireMessage::text("0{\"sid\":\"live\",\"upgrades\":[],\"pingInterval\":25000,\"pingTimeout\":20000}"),0).unwrap();
        assert_eq!(
            session_deadline(&input, &observed, 0, started),
            started + Duration::from_millis(input.policy.max_duration_ms)
        );
        assert_eq!(
            session_deadline(&input, &observed, 1, started),
            started + Duration::from_millis(input.policy.business_idle_ms)
        );
    }

    #[test]
    fn input_gap_compression_waits_for_independently_observed_target_completion() {
        let sent = Instant::now();
        let action = InputAction {
            sequence: 2,
            offset_ms: 30_000,
            after: vec![1],
            compressible_gap: true,
            gap_start_ms: Some(2_000),
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text("42[\"next\"]"),
            },
        };
        let mut completed = BTreeMap::new();
        assert!(websocket_action_due(&action, &completed, 0, sent, 100).is_none());
        let target_done = sent + Duration::from_secs(2);
        completed.insert(1, target_done);
        assert_eq!(
            websocket_action_due(&action, &completed, 0, sent, 100),
            Some(target_done + Duration::from_millis(100))
        );
        let overlap = InputAction {
            after: vec![],
            compressible_gap: false,
            ..action
        };
        assert_eq!(
            websocket_action_due(&overlap, &completed, 0, sent, 100),
            Some(sent + Duration::from_secs(30))
        );
    }

    #[test]
    fn explicit_close_preserves_the_gap_after_actual_completion() {
        let sent = Instant::now();
        let target_done = sent + Duration::from_millis(40);
        let mut completed = BTreeMap::new();
        let mut action = InputAction {
            sequence: 3,
            offset_ms: 57,
            after: vec![2],
            compressible_gap: false,
            gap_start_ms: Some(7),
            ack_ref: None,
            action: InputActionKind::Close {
                code: None,
                reason: String::new(),
            },
        };
        assert!(websocket_action_due(&action, &completed, 10, sent, 1).is_none());
        completed.insert(2, target_done);
        assert_eq!(
            websocket_action_due(&action, &completed, 10, sent, 1),
            Some(target_done + Duration::from_millis(50))
        );
        action.action = InputActionKind::Message {
            message: WireMessage::text("1"),
        };
        assert_eq!(
            websocket_action_due(&action, &completed, 10, sent, 1),
            Some(sent + Duration::from_millis(47)),
            "a generic WebSocket text message is not an Engine.IO close"
        );
    }
}

#[cfg(test)]
mod net_tests;
