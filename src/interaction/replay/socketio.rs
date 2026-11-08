//! Fresh sessions share one scheduler; completion uses only actual Target traffic.
mod dispatch;
mod heartbeat;
mod namespace;
mod transport;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use std::collections::BTreeMap;
use tokio::time::{Duration, Instant, sleep_until};

use super::event_order::attachment;
use super::timing::{
    Advance, SOCKET_IO_DISPATCH_WAIT, cancellation, delivery_prefix, ordered_input,
    transport_cancellation, websocket_action_due,
};
use super::{Feedback, HttpClient, NativeEvent, ReplayResponse, elapsed_ms};
use crate::interaction::{
    lifecycle::LifecycleDecision,
    model::{
        ClientTransportEnd, DispatchStage, DispatchTimeout, EndReason, InputAction,
        InputActionKind, InputTranscript, Protocol, WireMessage,
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
        mut event_order,
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
    let mut dispatch = None::<dispatch::Dispatch>;
    let mut dispatch_anchor = Instant::now();
    let mut dispatch_timeout = None;
    let fast_tail = input_timing.as_ref().and_then(|timing| timing.fast_tail());
    let heartbeat_timeout = fast_tail
        .as_ref()
        .is_some_and(|tail| tail.heartbeat_timeout);
    let mut terminal = heartbeat::Terminal::default();
    let mut tail_wait: Option<futures_util::future::BoxFuture<'static, Result<Advance>>> = None;
    let mut tail_ready_at: Option<Instant> = None;
    let mut tail_compressed = false;
    let mut output_count = 0;
    let mut last_output = started;
    let mut heartbeats =
        heartbeat::Heartbeats::new(transcript, heartbeat_timeout && transport.is_websocket());
    let mut namespaces = namespace::Admission::default();
    let has_transport_end = transcript
        .actions
        .last()
        .is_some_and(|action| matches!(action.action, InputActionKind::TransportEnd { .. }));
    let ordered_inputs = ordered_fast.then(|| {
        transcript
            .actions
            .iter()
            .map(ordered_input)
            .collect::<Vec<_>>()
    });
    let mut missing_predecessor = None;
    let (mut reason, mut transport_clean) = 'session: loop {
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
        let awaiting_terminal_ping =
            heartbeat_timeout && transport.is_websocket() && next == transcript.actions.len();
        if awaiting_terminal_ping {
            // Case-level rejection remains in the dependency report. Keep the
            // actual peer open so its disconnect handler still runs.
            dependency_failure = None;
        } else if dependency_failure
            .as_ref()
            .is_some_and(|failure| *failure.borrow())
        {
            break (EndReason::DependencyFailure, false);
        }
        let now = elapsed_ms(started);
        match observed.decision(now) {
            LifecycleDecision::Close(EndReason::BusinessIdle)
                if awaiting_terminal_ping
                    || (transcript.protocol == Protocol::SocketIo || has_transport_end)
                        && next < transcript.actions.len() => {}
            LifecycleDecision::Close(reason) => break (reason, true),
            LifecycleDecision::Fail(EndReason::RequestTimeout) if awaiting_terminal_ping => {}
            LifecycleDecision::Fail(reason) => break (reason, false),
            _ => {}
        }
        let action = transcript.actions.get(next);
        let ordered =
            action.is_some() && ordered_inputs.as_ref().is_some_and(|inputs| inputs[next]);
        let namespace_close = ordered_fast
            && action
                .is_some_and(|a| namespace::disconnects(a, transcript.policy.max_message_bytes));
        let missing_event = event_order
            .as_ref()
            .zip(action.filter(|_| ordered || namespace_close))
            .and_then(|(order, action)| order.missing(action));
        let dispatch_deadline = (ordered || namespace_close && missing_event.is_some())
            .then_some(dispatch_anchor + SOCKET_IO_DISPATCH_WAIT);
        let namespace_ready = transcript.protocol != Protocol::SocketIo
            || action.is_none_or(|action| {
                namespaces.permits(action, transcript.policy.max_message_bytes)
            });
        let prerequisites_ready = action.filter(|_| namespace_ready).filter(|action| {
            transcript.protocol != Protocol::SocketIo
                || action.after.iter().all(|id| completed.contains_key(id))
        });
        let admitted = prerequisites_ready
            .filter(|_| !namespace_close || missing_event.is_none())
            .filter(|action| {
                action.ack_ref.as_ref().is_none_or(|reference| {
                    server_acks.contains_key(&(
                        reference.namespace.clone(),
                        reference.server_event_ordinal,
                    ))
                })
            });
        let events_ready = missing_event.is_none() && admitted.is_some();
        if dispatch_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let unadmitted = dispatch.as_ref().and_then(dispatch::Dispatch::unadmitted);
            dispatch_timeout = Some(DispatchTimeout {
                input_sequence: action.expect("ordered input").sequence,
                stage: if missing_event.is_some() || unadmitted.is_some() || admitted.is_none() {
                    DispatchStage::Prerequisites
                } else {
                    DispatchStage::Timing
                },
                unadmitted_request: unadmitted,
            });
            missing_predecessor = missing_event;
            let reason = if missing_event.is_some() {
                EndReason::MissingPredecessor
            } else {
                EndReason::DispatchTimeout
            };
            break (reason, false);
        }
        if let Some(dispatch) = &dispatch
            && events_ready
        {
            dispatch.events_arrived();
        }
        let at_fast_tail = fast_tail.as_ref().is_some_and(|tail| {
            let at_boundary = match tail.close_sequence {
                Some(sequence) => admitted.is_some_and(|action| action.sequence == sequence),
                None => action.is_none(),
            };
            at_boundary
                && output_count >= tail.output_count
                && (tail.native_observation
                    || !tail.heartbeat_timeout && observed.pending().is_empty())
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
            .filter(|_| at_fast_tail)
            .zip(tail_ready_at)
            .and_then(|(tail, ready)| tail.business_idle_due(ready, last_sent, last_output));
        // The dispatch window can release the native push that produces an ACK's
        // server event. Open it before that event arrives, while keeping the
        // input gated on the live ACK identity.
        let timing_action = if ordered {
            prerequisites_ready
        } else {
            admitted
        };
        if let (Some(action), Some(timing)) = (timing_action, &input_timing)
            && (ordered || action.compressible_gap || delivery_prefix(action))
            && !cancellation(action)
            && timing_sequence != Some(action.sequence)
        {
            let timing = timing.clone();
            timing_sequence = Some(action.sequence);
            timing_wait = Some(if ordered {
                let (pending, wait) = dispatch::Dispatch::begin(timing, action, events_ready);
                dispatch = Some(pending);
                wait
            } else {
                let (sequence, completed) = (action.sequence, action.after.clone());
                Box::pin(async move { timing.wait(sequence, completed).await })
            });
        }
        // An input released on its original deadline can be later than the
        // compressed clock. Pace ordered closes from the preceding actual send.
        let ordered_close_due = admitted
            .filter(|action| ordered_fast && !tail_compressed && cancellation(action))
            .map(|action| {
                last_sent + Duration::from_millis(action.offset_ms.saturating_sub(last_offset))
            });
        let due = admitted.and_then(|action| {
            if ordered {
                return (timing_ready == Some(action.sequence) && missing_event.is_none())
                    .then(Instant::now);
            }
            if ordered_fast && attachment(action) {
                // Retain the wire spacing after a compressed binary header.
                return Some(
                    last_sent + Duration::from_millis(action.offset_ms.saturating_sub(last_offset)),
                );
            }
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
        let due = due.into_iter().chain(ordered_close_due).max();
        let lifecycle_deadline = if awaiting_terminal_ping {
            started + Duration::from_millis(transcript.policy.max_duration_ms)
        } else {
            session_deadline(transcript, &observed, next, started)
        };
        // A recorded transport cancellation must remain available while an
        // earlier input is waiting for an ACK, namespace or dependency delivery.
        let cancel = transcript.actions.iter().skip(next + 1).find(|action| {
            transport_cancellation(action)
                && ((!(ordered || namespace_close) && transcript.protocol == Protocol::SocketIo)
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
        let heartbeat_due = heartbeats.next_due().filter(|_| !awaiting_terminal_ping);
        let io_deadline =
            dispatch_deadline.map_or(lifecycle_deadline, |due| due.min(lifecycle_deadline));
        macro_rules! session_io {
            ($future:expr, $context:literal) => {
                session_io!(result tokio::time::timeout_at(io_deadline, $future).await, $context)
            };
            (result $result:expr, $context:literal) => {
                match $result {
                    Err(_) if dispatch_deadline == Some(io_deadline) => continue 'session,
                    result => result.context($context)??,
                }
            };
        }
        tokio::select! {
            biased;
            _ = async { match dependency_failure.as_mut() {
                Some(failure) => {let _=failure.changed().await;},
                None => std::future::pending::<()>().await,
            } } => {
                if dependency_failure.as_ref().is_some_and(|failure|*failure.borrow()) {break (EndReason::DependencyFailure,false);}
                dependency_failure=None;
            }
            _ = sleep_until(dispatch_deadline.unwrap_or(lifecycle_deadline)), if dispatch_deadline.is_some() => continue 'session,
            _ = sleep_until(cancel_due.unwrap_or(lifecycle_deadline)), if ordered_close_due.is_none() && cancel_due.is_some_and(|cancel| due.is_none_or(|due| due > cancel)) => {
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
                                if let (Some(order), EngineIoPacket::Message(packet)) = (&mut event_order, &packet)
                                    && order.observe(packet) && missing_event.is_some() {
                                    dispatch_anchor = Instant::now();
                                }
                                if awaiting_terminal_ping
                                    && matches!(&packet, EngineIoPacket::Message(packet)
                                        if matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent
                                            | SocketIoKind::Ack | SocketIoKind::BinaryAck))
                                    && let Some(pong) = terminal.business_output(Instant::now())
                                {
                                    session_io!(transport.send(&pong), "deferred Engine.IO heartbeat send timed out");
                                }
                                match packet {
                                    EngineIoPacket::Open(open) => {
                                        terminal.configure(open.ping_timeout);
                                        transport.set_sid(open.sid)?;
                                    }
                                    EngineIoPacket::Message(packet) if packet.kind == SocketIoKind::Connect => {
                                        namespaces.accept(&packet.namespace);
                                        if let Some(sink) = &native_events {
                                            tokio::select! {
                                                biased;
                                                _ = crate::dependency::execution::rejected(&mut dependency_failure) => break 'session (EndReason::DependencyFailure, false),
                                                result = tokio::time::timeout_at(io_deadline, sink.connected(&packet.namespace, packet.data.as_ref().and_then(|data| data.get("sid")).and_then(serde_json::Value::as_str))) => {
                                                    session_io!(result result, "native namespace observation timed out");
                                                }
                                            }
                                        }
                                    }
                                    EngineIoPacket::Ping(payload) => {
                                        let now = Instant::now();
                                        if awaiting_terminal_ping {
                                            terminal.defer_pong(payload, now);
                                        } else if heartbeats.ping(payload.clone(), now)? {
                                            session_io!(transport.send(&WireMessage::text(format!("3{payload}"))), "Engine.IO heartbeat send timed out");
                                        }
                                    }
                                    EngineIoPacket::Message(packet) if matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck) => {
                                        if let Some(sequence) = native_receipts.acknowledge(&packet) && let Some(sink) = &native_events {
                                            if ordered {
                                                session_io!(sink.acknowledged(sequence), "native ACK observation timed out");
                                            } else {
                                                sink.acknowledged(sequence).await?;
                                            }
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
                                                result = tokio::time::timeout_at(io_deadline, sink.observe(event)) => {
                                                    session_io!(result result, "native event observation timed out");
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
                        session_io!(transport.pong(bytes), "WebSocket heartbeat send timed out");
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
                session_io!(transport.send(&message), "recorded Engine.IO heartbeat send timed out");
            }
            _ = sleep_until(wake) => {
                if fast_idle_due.is_some_and(|due| Instant::now() >= due) {
                    break (EndReason::BusinessIdle, true);
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
                            let policy_deadline = started + Duration::from_millis(observed.next_deadline_ms());
                            let deadline = dispatch_deadline.map_or(policy_deadline, |deadline| deadline.min(policy_deadline));
                            match tokio::time::timeout_at(deadline, transport.send(&message)).await {
                                Err(_) if dispatch_deadline == Some(deadline) => {
                                    dispatch_timeout = Some(DispatchTimeout {
                                        input_sequence: action.sequence, stage: DispatchStage::Send, unadmitted_request: None,
                                    });
                                    break (EndReason::DispatchTimeout, false);
                                }
                                result => result.context("Target session input send timed out")??,
                            }
                            if !control {
                                dispatch_anchor = Instant::now();
                            }
                            if native_events.is_some() && transcript.protocol == Protocol::SocketIo {
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
                        dispatch_anchor = Instant::now();
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
                dispatch = None;
                next += 1;
                last_offset = action.offset_ms;
                last_sent = Instant::now();
            }
        }
    };
    let cleanup = Duration::from_millis(transcript.policy.cleanup_timeout_ms);
    let mut closed = reason == EndReason::ServerEof || transport.raw_end_complete();
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
    if !closed && dispatch_timeout.is_none() {
        let _ = tokio::time::timeout(
            cleanup,
            transport.abort(Some(1000), "recording case complete"),
        )
        .await;
    }
    let heartbeat_eof = (reason == EndReason::ServerEof && terminal.expired(Instant::now()))
        .then(|| elapsed_ms(started));
    let (actual_input, mut observation) = observed.finish(
        reason,
        elapsed_ms(started),
        transport_clean
            && closed
            && next == transcript.actions.len()
            && (heartbeat_eof.is_some()
                || heartbeats.complete(
                    removed_ms > 0
                        && matches!(
                            reason,
                            EndReason::ClientClose | EndReason::ClientTransportEnd
                        ),
                )),
    )?;
    observation.end.fast_heartbeat_eof_ms = heartbeat_eof;
    observation.end.missing_predecessor = missing_predecessor;
    observation.end.dispatch_timeout = dispatch_timeout;
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
mod tests;

#[cfg(test)]
mod net_tests;
