//! Fresh sessions share one scheduler; completion uses only actual Target traffic.
mod heartbeat;
mod transport;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use std::collections::BTreeMap;
use tokio::time::{Duration, Instant, sleep_until};

use super::{HttpClient, ReplayResponse, elapsed_ms};
use crate::interaction::{
    lifecycle::LifecycleDecision,
    model::{EndReason, InputAction, InputActionKind, InputTranscript, Protocol, WireMessage},
    observation::Observation,
    socketio::{EngineIoPacket, SocketIoDecoder, SocketIoKind},
};
use transport::{ReaderEvent, Transport};

pub(super) async fn execute_with_feedback(
    client: &HttpClient,
    origin: &str,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
    mut dependency_failure: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<ReplayResponse> {
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
    let mut pending_receipts = std::collections::BTreeSet::new();
    let mut heartbeats = heartbeat::Heartbeats::new(transcript);
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
            LifecycleDecision::Close(reason) => break (reason, true),
            LifecycleDecision::Fail(reason) => break (reason, false),
            _ => {}
        }
        let action = transcript.actions.get(next);
        let due = action
            .filter(|action| {
                transcript.policy.preserve_input_timing
                    || pending_receipts.is_empty()
                    || allows_pending_receipts(action)
            })
            .filter(|action| {
                action.ack_ref.as_ref().is_none_or(|reference| {
                    server_acks.contains_key(&(
                        reference.namespace.clone(),
                        reference.server_event_ordinal,
                    ))
                })
            })
            .and_then(|action| {
                action_due(
                    transcript.protocol,
                    action,
                    &completed,
                    last_offset,
                    last_sent,
                    transcript.policy.input_gap_ms,
                    transcript.policy.preserve_input_timing,
                )
            });
        let lifecycle_deadline = started + Duration::from_millis(observed.next_deadline_ms());
        let wake = due.map_or(lifecycle_deadline, |due| due.min(lifecycle_deadline));
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
            incoming = transport.recv() => {
                match incoming.context("Target session reader stopped")? {
                    ReaderEvent::Message(message) => {
                        let before = observed.pending();
                        observed.output(message.clone(), elapsed_ms(started))?;
                        note_completed(before, &observed, &mut completed);
                        if transcript.protocol == Protocol::SocketIo {
                            for packet in server_decoder.push(&message)? {
                                match packet {
                                    EngineIoPacket::Open(open) => transport.set_sid(open.sid)?,
                                    EngineIoPacket::Ping(payload) => {
                                        if heartbeats.ping(payload.clone(), Instant::now())? {
                                            tokio::time::timeout_at(lifecycle_deadline,
                                                transport.send(&WireMessage::text(format!("3{payload}"))))
                                                .await.context("Engine.IO heartbeat send timed out")??;
                                        }
                                    }
                                    EngineIoPacket::Message(packet) if matches!(packet.kind,SocketIoKind::Ack | SocketIoKind::BinaryAck) => {
                                        if let Some(id)=packet.id {pending_receipts.remove(&(packet.namespace,id));}
                                    }
                                    EngineIoPacket::Message(packet) if matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent) => {
                                        let ordinal = server_ordinals.entry(packet.namespace.clone()).or_default();
                                        *ordinal += 1;
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
                let Some(action) = action.filter(|_| due.is_some_and(|due| Instant::now() >= due)) else { continue; };
                match &action.action {
                    InputActionKind::Message { message } => {
                        let message = if transcript.protocol == Protocol::SocketIo { rebind_ack(message, action, &server_acks)? } else { message.clone() };
                        if transcript.protocol==Protocol::SocketIo && !transcript.policy.preserve_input_timing && message.kind==crate::interaction::model::MessageKind::Text
                            && let EngineIoPacket::Message(packet)=crate::interaction::socketio::decode_engine_io_text(&message.data,transcript.policy.max_message_bytes)?
                            && matches!(packet.kind,SocketIoKind::Event|SocketIoKind::BinaryEvent) && let Some(id)=packet.id {
                            pending_receipts.insert((packet.namespace,id));
                        }
                        let actual_action = observed.input(message.clone(), elapsed_ms(started))?;
                        ensure!(actual_action.sequence == action.sequence, "recorded session input identity is inconsistent; re-record this case");
                        // Source heartbeats never drive the Target heartbeat clock.
                        let control = transcript.protocol == Protocol::SocketIo
                            && message.kind == crate::interaction::model::MessageKind::Text
                            && crate::interaction::socketio::decode_engine_io_text(&message.data, transcript.policy.max_message_bytes)?.is_heartbeat();
                        if !control || heartbeats.recorded_pong(&message, transcript.policy.max_message_bytes)? {
                            tokio::time::timeout_at(started + Duration::from_millis(observed.next_deadline_ms()),
                                transport.send(&message)).await.context("Target session input send timed out")??;
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
                }
                next += 1;
                last_offset = action.offset_ms;
                last_sent = Instant::now();
            }
        }
    };
    let cleanup = Duration::from_millis(transcript.policy.cleanup_timeout_ms);
    let mut closed = reason == EndReason::ServerEof;
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
    let (_, observation) = observed.finish(
        reason,
        elapsed_ms(started),
        transport_clean
            && closed
            && next == transcript.actions.len()
            && heartbeats.complete(
                !transcript.policy.preserve_input_timing && reason == EndReason::ClientClose,
            ),
    )?;
    Ok(ReplayResponse {
        started_at,
        status: transport.status,
        headers: transport.headers.clone(),
        body: Bytes::new(),
        observation,
    })
}

#[cfg(test)]
async fn execute(
    client: &HttpClient,
    origin: &str,
    request: Request<Full<Bytes>>,
    transcript: &InputTranscript,
    header_timeout: Duration,
) -> Result<ReplayResponse> {
    execute_with_feedback(client, origin, request, transcript, header_timeout, None).await
}

fn allows_pending_receipts(action: &InputAction) -> bool {
    // Overlapping business inputs retain their recorded order. Drain requested
    // native receipts only before ending their namespace; transport cancellation
    // remains an explicit client input and may end pending business.
    !matches!(&action.action,InputActionKind::Message {message}
        if message.kind==crate::interaction::model::MessageKind::Text
        && matches!(crate::interaction::socketio::decode_engine_io_text(&message.data,usize::MAX),Ok(EngineIoPacket::Message(packet)) if packet.kind==SocketIoKind::Disconnect))
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

fn action_due(
    protocol: Protocol,
    action: &InputAction,
    completed: &BTreeMap<u64, Instant>,
    last_offset: u64,
    last_sent: Instant,
    input_gap_ms: u64,
    preserve_input_timing: bool,
) -> Option<Instant> {
    let fast = protocol == Protocol::SocketIo && !preserve_input_timing;
    let gap = |delay: u64| if fast { 0 } else { delay };
    let mut barrier = None;
    for sequence in &action.after {
        let at = *completed.get(sequence)?;
        barrier = Some(barrier.map_or(at, |previous: Instant| previous.max(at)));
    }
    let closes = matches!(action.action, InputActionKind::Close { .. })
        || (protocol == Protocol::SocketIo
            && matches!(&action.action, InputActionKind::Message { message }
                if message.kind == crate::interaction::model::MessageKind::Text
                    && message.data == "1"));
    if closes && let Some(gap_start) = action.gap_start_ms {
        let delay = action.offset_ms.checked_sub(gap_start)?;
        // Keep the actual completion barrier even when client idle time is compressed.
        return barrier?.checked_add(Duration::from_millis(gap(delay)));
    }
    if action.compressible_gap {
        let gap_start = action.gap_start_ms?;
        let delay = gap(action.offset_ms.saturating_sub(gap_start).min(input_gap_ms));
        Some(barrier? + Duration::from_millis(delay))
    } else {
        let due =
            last_sent + Duration::from_millis(gap(action.offset_ms.saturating_sub(last_offset)));
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
        assert!(action_due(Protocol::SocketIo, &action, &completed, 0, sent, 100, true).is_none());
        let target_done = sent + Duration::from_secs(2);
        completed.insert(1, target_done);
        assert_eq!(
            action_due(Protocol::SocketIo, &action, &completed, 0, sent, 100, true),
            Some(target_done + Duration::from_millis(100))
        );
        let overlap = InputAction {
            after: vec![],
            compressible_gap: false,
            ..action
        };
        assert_eq!(
            action_due(Protocol::SocketIo, &overlap, &completed, 0, sent, 100, true),
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
        assert!(action_due(Protocol::SocketIo, &action, &completed, 10, sent, 1, true).is_none());
        completed.insert(2, target_done);
        assert_eq!(
            action_due(Protocol::SocketIo, &action, &completed, 10, sent, 1, true),
            Some(target_done + Duration::from_millis(50))
        );
        action.action = InputActionKind::Message {
            message: WireMessage::text("1"),
        };
        assert_eq!(
            action_due(Protocol::SocketIo, &action, &completed, 10, sent, 1, true),
            Some(target_done + Duration::from_millis(50))
        );
        assert_eq!(
            action_due(Protocol::WebSocket, &action, &completed, 10, sent, 1, true),
            Some(sent + Duration::from_millis(47)),
            "a generic WebSocket text message is not an Engine.IO close"
        );
    }
}

#[cfg(test)]
mod net_tests;
