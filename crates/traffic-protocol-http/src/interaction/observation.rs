//! Compose protocol observations and lifecycle without transport or persistence.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::{
    heartbeat::RecordedHeartbeats,
    lifecycle::{InteractionLifecycle, LifecycleDecision},
    model::{
        AckReference, CloseObservation, EndReason, HttpStreamMode, InputAction, InputActionKind,
        InputTranscript, MessageKind, OutputEvent, OutputObservation, Protocol, TRANSCRIPT_VERSION,
        WireMessage,
    },
    policy::InteractionPolicy,
    socketio::{
        AckFailureKind, AckObservationError, CompletionTracker, CompletionUpdate, EngineIoPacket,
        SocketIoDecoder, SocketIoKind, decode_engine_io_text,
    },
    stream::{StreamDecoder, StreamMessage},
};

mod client_end;

const CLIENT_BINARY_PENDING: u64 = u64::MAX - 1;
const SERVER_BINARY_PENDING: u64 = u64::MAX - 2;

/// Legacy or precise elapsed time at the point a client input is observed.
pub struct InputTime {
    ms: u64,
    us: Option<u64>,
}

impl From<u64> for InputTime {
    fn from(ms: u64) -> Self {
        Self { ms, us: None }
    }
}

impl From<Duration> for InputTime {
    fn from(elapsed: Duration) -> Self {
        let us = elapsed.as_micros().try_into().ok();
        Self {
            ms: elapsed.as_millis().try_into().unwrap_or(u64::MAX),
            us,
        }
    }
}

#[cfg(test)]
mod peer_close_tests;
#[cfg(test)]
mod subscription_tests;

/// One fresh physical session. Its expected outputs are never part of its input program.
pub struct Observation {
    protocol: Protocol,
    policy: InteractionPolicy,
    lifecycle: InteractionLifecycle,
    tracker: CompletionTracker,
    client_decoder: SocketIoDecoder,
    server_decoder: SocketIoDecoder,
    stream_decoder: Option<StreamDecoder>,
    close_barrier: Option<(Vec<u64>, u64)>,
    input: InputTranscript,
    output: Vec<OutputEvent>,
    server_ordinals: BTreeMap<String, u64>,
    server_ack_ordinals: BTreeMap<(String, u64), u64>,
    safe_barrier: Option<(Vec<u64>, u64)>,
    pending_upgrade: Option<u64>,
    close: Option<CloseObservation>,
    server_end_observed: bool,
    heartbeats: RecordedHeartbeats,
    next_input: u64,
    next_output: u64,
}

impl Observation {
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    pub fn policy(&self) -> &InteractionPolicy {
        &self.policy
    }

    /// Dependency reservations and completions can invalidate a seemingly idle gap.
    /// The Source-global registry supplies monotonic times before accepting input.
    pub fn dependency_activity(&mut self, now_ms: u64) {
        if self
            .safe_barrier
            .as_ref()
            .is_some_and(|(_, completed)| now_ms >= *completed)
        {
            self.safe_barrier = None;
        }
    }

    pub fn new(protocol: Protocol, policy: InteractionPolicy) -> Result<Self> {
        Self::with_http_stream_mode(protocol, policy, HttpStreamMode::Response)
    }

    pub fn new_sse_subscription(policy: InteractionPolicy, now_ms: u64) -> Result<Self> {
        let mut observation =
            Self::with_http_stream_mode(Protocol::Sse, policy, HttpStreamMode::Subscription)?;
        // Header acquisition is not subscription business silence.
        observation.lifecycle.activity(now_ms);
        Ok(observation)
    }

    fn with_http_stream_mode(
        protocol: Protocol,
        policy: InteractionPolicy,
        mode: HttpStreamMode,
    ) -> Result<Self> {
        policy.validate()?;
        ensure!(
            protocol != Protocol::WebSocket || policy.stream_terminal.is_some(),
            "generic WebSocket requires an explicit terminal completion rule"
        );
        let mut lifecycle = InteractionLifecycle::new(policy.clone(), 0)?;
        if mode == HttpStreamMode::Response {
            lifecycle.begin(0, 0)?;
        }
        let mut input = InputTranscript::new(protocol, policy.clone());
        input.http_stream_mode = mode;
        input.validate()?;
        let stream_decoder = if matches!(
            protocol,
            Protocol::Sse | Protocol::Ndjson | Protocol::RawStream
        ) {
            Some(StreamDecoder::new(protocol, policy.max_message_bytes)?)
        } else {
            None
        };
        Ok(Self {
            protocol,
            tracker: CompletionTracker::new(policy.clone()),
            client_decoder: SocketIoDecoder::new(policy.max_message_bytes),
            server_decoder: SocketIoDecoder::new(policy.max_message_bytes),
            stream_decoder,
            close_barrier: None,
            input,
            policy,
            lifecycle,
            output: Vec::new(),
            server_ordinals: BTreeMap::new(),
            server_ack_ordinals: BTreeMap::new(),
            safe_barrier: None,
            pending_upgrade: None,
            close: None,
            server_end_observed: false,
            heartbeats: RecordedHeartbeats::default(),
            next_input: 1,
            next_output: 1,
        })
    }

    pub fn input(
        &mut self,
        message: WireMessage,
        now: impl Into<InputTime>,
    ) -> Result<InputAction> {
        let InputTime { ms: now_ms, us } = now.into();
        self.ensure_client_transport_open()?;
        ensure!(
            matches!(self.protocol, Protocol::SocketIo | Protocol::WebSocket),
            "HTTP stream inputs are carried by the primary HTTP request"
        );
        self.lifecycle.record_message(message.decode()?.len())?;
        let sequence = self.next_input;
        self.next_input += 1;
        let mut action = InputAction {
            sequence,
            offset_ms: now_ms,
            offset_us: us,
            after: Vec::new(),
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: message.clone(),
            },
        };
        let idle_before = self.lifecycle.pending().is_empty();
        let barrier = self.safe_barrier.clone();
        let mut business = self.protocol == Protocol::WebSocket;
        if self.protocol == Protocol::SocketIo {
            if message.kind == MessageKind::Text {
                ensure!(
                    !message.data.contains('\u{1e}'),
                    "observe polling packets individually"
                );
                if let EngineIoPacket::Message(packet) =
                    decode_engine_io_text(&message.data, self.policy.max_message_bytes)?
                    && matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck)
                {
                    let key = (packet.namespace.clone(), packet.id.unwrap());
                    action.ack_ref = Some(AckReference {
                        namespace: packet.namespace,
                        server_event_ordinal: *self.server_ack_ordinals.get(&key).ok_or_else(
                            || AckObservationError::new(AckFailureKind::ClientAckUnobserved, key.1),
                        )?,
                    });
                }
            }
            let was_partial = self.client_decoder.has_pending_binary();
            let packets = self.client_decoder.push(&message)?;
            self.binary_transition(
                was_partial,
                self.client_decoder.has_pending_binary(),
                CLIENT_BINARY_PENDING,
                now_ms,
            )?;
            for packet in packets {
                match packet {
                    EngineIoPacket::Message(packet) => {
                        let update = self.tracker.observe_client(sequence, &packet, now_ms)?;
                        business |= update.business;
                        self.apply_update(update, now_ms)?;
                    }
                    EngineIoPacket::Upgrade => {
                        if let Some(upgrade) = self.pending_upgrade.take() {
                            self.lifecycle.complete(upgrade, now_ms)?;
                            self.note_completion(upgrade, now_ms);
                        }
                    }
                    EngineIoPacket::Pong(payload) => {
                        self.heartbeats.pong(&payload, sequence, now_ms)
                    }
                    _ => {}
                }
            }
        } else {
            ensure!(
                self.lifecycle.pending().is_empty() || self.lifecycle.pending() == vec![0],
                "generic WebSocket does not support overlapping uncorrelated requests"
            );
            if self.lifecycle.is_pending(0) {
                self.lifecycle.complete(0, now_ms)?;
            }
            self.lifecycle.begin(sequence, now_ms)?;
        }
        if business {
            if idle_before && let Some((after, at)) = barrier {
                action.after = after;
                action.gap_start_ms = Some(at);
                action.compressible_gap = !self.policy.preserve_input_timing;
            }
            self.safe_barrier = None;
            self.lifecycle.activity(now_ms);
        }
        if self.protocol == Protocol::SocketIo
            && message.kind == MessageKind::Text
            && message.data == "1"
            && self.lifecycle.pending().is_empty()
            && let Some((after, at)) = &self.close_barrier
        {
            action.after = after.clone();
            action.gap_start_ms = Some(*at);
            action.compressible_gap = false;
        }
        self.input.actions.push(action.clone());
        Ok(action)
    }

    pub fn output(&mut self, message: WireMessage, now_ms: u64) -> Result<OutputEvent> {
        self.lifecycle.record_message(message.decode()?.len())?;
        let mut heartbeat = false;
        if self.protocol == Protocol::SocketIo {
            if message.kind == MessageKind::Text {
                ensure!(
                    !message.data.contains('\u{1e}'),
                    "observe polling packets individually"
                );
            }
            let was_partial = self.server_decoder.has_pending_binary();
            let packets = self.server_decoder.push(&message)?;
            self.binary_transition(
                was_partial,
                self.server_decoder.has_pending_binary(),
                SERVER_BINARY_PENDING,
                now_ms,
            )?;
            heartbeat = !packets.is_empty() && packets.iter().all(EngineIoPacket::is_heartbeat);
            for packet in packets {
                match packet {
                    EngineIoPacket::Open(_) => {
                        if self.lifecycle.is_pending(0) {
                            self.lifecycle.complete(0, now_ms)?;
                        }
                    }
                    EngineIoPacket::Message(packet) => {
                        if packet.event_name().is_some() {
                            let ordinal = self
                                .server_ordinals
                                .entry(packet.namespace.clone())
                                .or_default();
                            *ordinal += 1;
                            if let Some(id) = packet.id {
                                self.server_ack_ordinals
                                    .insert((packet.namespace.clone(), id), *ordinal);
                            }
                        }
                        let update = self.tracker.observe_server(&packet, now_ms)?;
                        self.apply_update(update, now_ms)?;
                    }
                    EngineIoPacket::Ping(payload) => self.heartbeats.ping(payload, now_ms),
                    EngineIoPacket::Close => self.server_end_observed = true,
                    _ => {}
                }
            }
        } else if self.protocol == Protocol::WebSocket {
            let observed = StreamMessage {
                message: message.clone(),
                heartbeat: false,
            };
            if observed.is_terminal_for(self.protocol, &self.policy.stream_terminal)? {
                let pending = self.lifecycle.pending();
                ensure!(pending.len() <= 1, "ambiguous generic WebSocket completion");
                for id in pending {
                    self.lifecycle.complete(id, now_ms)?;
                    self.note_completion(id, now_ms);
                }
            }
        }
        if !heartbeat {
            self.lifecycle.activity(now_ms);
        }
        let event = OutputEvent {
            sequence: self.next_output,
            offset_ms: now_ms,
            message,
            heartbeat,
        };
        self.next_output += 1;
        self.output.push(event.clone());
        Ok(event)
    }

    pub fn stream_bytes(&mut self, bytes: &[u8], now_ms: u64) -> Result<()> {
        let messages = self
            .stream_decoder
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not a framed HTTP stream"))?
            .feed(bytes)?;
        self.stream_messages(messages, now_ms)?;
        Ok(())
    }

    pub fn stream_eof(&mut self, now_ms: u64) -> Result<()> {
        let messages = self
            .stream_decoder
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not a framed HTTP stream"))?
            .finish()?;
        self.stream_messages(messages, now_ms)?;
        if self.lifecycle.is_pending(0) {
            self.lifecycle.complete(0, now_ms)?;
        }
        Ok(())
    }

    pub fn upgrade(
        &mut self,
        uri: String,
        headers: BTreeMap<String, Vec<String>>,
        now: impl Into<InputTime>,
    ) -> Result<InputAction> {
        let InputTime { ms: now_ms, us } = now.into();
        self.ensure_client_transport_open()?;
        ensure!(
            self.protocol == Protocol::SocketIo,
            "only Socket.IO sessions support polling upgrade actions"
        );
        ensure!(
            self.pending_upgrade.is_none(),
            "Socket.IO upgrade already pending"
        );
        let action = InputAction {
            sequence: self.next_input,
            offset_ms: now_ms,
            offset_us: us,
            after: Vec::new(),
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Upgrade { uri, headers },
        };
        self.next_input += 1;
        self.lifecycle.begin(action.sequence, now_ms)?;
        self.pending_upgrade = Some(action.sequence);
        self.safe_barrier = None;
        self.input.actions.push(action.clone());
        Ok(action)
    }

    pub fn pending(&self) -> Vec<u64> {
        self.lifecycle.pending()
    }
    pub fn decision(&self, now_ms: u64) -> LifecycleDecision {
        self.lifecycle.decision(now_ms)
    }
    pub fn next_deadline_ms(&self) -> u64 {
        self.lifecycle.next_deadline_ms()
    }

    pub fn finish(
        &self,
        reason: EndReason,
        now_ms: u64,
        transport_clean: bool,
    ) -> Result<(InputTranscript, OutputObservation)> {
        self.client_decoder.finish()?;
        self.server_decoder.finish()?;
        let client_transport_end =
            self.input.actions.last().is_some_and(|action| {
                matches!(action.action, InputActionKind::TransportEnd { .. })
            });
        ensure!(
            reason != EndReason::ClientTransportEnd || client_transport_end,
            "client transport termination requires its actual recorded input"
        );
        ensure!(
            self.tracker
                .pending()
                .iter()
                .all(|id| self.lifecycle.is_pending(*id)),
            "Socket.IO protocol and lifecycle pending identities disagree"
        );
        let partial_message = if let Some(decoder) = &self.stream_decoder {
            if reason == EndReason::ClientClose {
                decoder.partial_message()
            } else {
                decoder.validate_boundary()?;
                None
            }
        } else {
            None
        };
        if let Some(partial) = &partial_message {
            ensure!(
                self.input
                    .actions
                    .last()
                    .is_some_and(|action| matches!(action.action, InputActionKind::Close { .. })),
                "partial stream observation requires a recorded client close input"
            );
            let length = partial.decode()?.len();
            let complete_bytes = self.output.iter().try_fold(0_usize, |total, event| {
                Ok::<_, anyhow::Error>(total.saturating_add(event.message.decode()?.len()))
            })?;
            ensure!(
                length <= self.policy.max_message_bytes
                    && self.output.len() < self.policy.max_messages
                    && complete_bytes.saturating_add(length) <= self.policy.max_total_bytes,
                "cancelled stream prefix exceeds observation budget"
            );
        }
        // An explicit peer WebSocket Close or Engine.IO CLOSE ends the captured
        // session even with pending RPCs. A bare EOF is not this evidence.
        let server_close = reason == EndReason::ServerEof
            && self.server_end_observed
            && matches!(self.protocol, Protocol::SocketIo | Protocol::WebSocket);
        let mut input = self.input.clone();
        if (server_close || client_transport_end) && self.protocol == Protocol::SocketIo {
            input.socket_io_heartbeat = Some(self.heartbeats.program());
        }
        input.validate()?;
        let mut end = self
            .lifecycle
            .end_observation(reason, now_ms, transport_clean);
        if server_close && transport_clean {
            end.clean = true;
        }
        if client_transport_end && reason != EndReason::ClientTransportEnd {
            end.clean = false;
        }
        end.partial_message = partial_message;
        if reason != EndReason::BusinessIdle {
            end.close = self.close.clone();
        }
        Ok((
            input,
            OutputObservation {
                version: TRANSCRIPT_VERSION,
                protocol: self.protocol,
                events: self.output.clone(),
                end,
            },
        ))
    }

    fn stream_messages(
        &mut self,
        messages: Vec<StreamMessage>,
        now_ms: u64,
    ) -> Result<Vec<OutputEvent>> {
        let mut events = Vec::new();
        for message in messages {
            self.lifecycle
                .record_message(message.message.decode()?.len())?;
            if message.is_terminal_for(self.protocol, &self.policy.stream_terminal)?
                && self.lifecycle.is_pending(0)
            {
                self.lifecycle.complete(0, now_ms)?;
                self.close_barrier = Some((vec![0], now_ms));
            }
            if !message.heartbeat {
                self.lifecycle.activity(now_ms);
            }
            let event = OutputEvent {
                sequence: self.next_output,
                offset_ms: now_ms,
                message: message.message,
                heartbeat: message.heartbeat,
            };
            self.next_output += 1;
            self.output.push(event.clone());
            events.push(event);
        }
        Ok(events)
    }

    fn apply_update(&mut self, update: CompletionUpdate, now_ms: u64) -> Result<()> {
        for id in update.started {
            self.lifecycle.begin(id, now_ms)?;
        }
        let mut completed = Vec::new();
        for id in update.completed {
            self.lifecycle.complete(id, now_ms)?;
            if id > 0 && id < (1 << 63) {
                completed.push(id);
            }
        }
        if !completed.is_empty() && self.lifecycle.pending().is_empty() {
            self.close_barrier = Some((completed.clone(), now_ms));
            self.safe_barrier = Some((completed, now_ms));
        } else if update.business {
            self.safe_barrier = None;
        }
        Ok(())
    }

    fn note_completion(&mut self, id: u64, now_ms: u64) {
        if id > 0 && id < (1 << 63) && self.lifecycle.pending().is_empty() {
            self.close_barrier = Some((vec![id], now_ms));
            self.safe_barrier = Some((vec![id], now_ms));
        }
    }

    fn binary_transition(&mut self, before: bool, after: bool, id: u64, now_ms: u64) -> Result<()> {
        if !before && after {
            self.lifecycle.begin(id, now_ms)?;
        }
        if before && !after {
            self.lifecycle.complete(id, now_ms)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::policy::{CompletionRule, EventCompletion, StreamTerminal};
    use super::*;

    fn completed_socketio_request() -> Observation {
        let policy = InteractionPolicy {
            completion: vec![EventCompletion {
                namespace: "/".into(),
                event: "ask".into(),
                completion: CompletionRule::Ack,
            }],
            ..Default::default()
        };
        let mut observation = Observation::new(Protocol::SocketIo, policy).unwrap();
        observation.output(open(), 0).unwrap();
        observation.input(WireMessage::text("40"), 0).unwrap();
        observation.output(WireMessage::text("40{}"), 0).unwrap();
        observation
            .input(WireMessage::text("421[\"ask\"]"), 0)
            .unwrap();
        observation.output(WireMessage::text("431[]"), 0).unwrap();
        observation
    }

    #[test]
    fn same_tick_socketio_close_waits_for_completed_input_without_compressing_its_gap() {
        for engine_io_close in [false, true] {
            let mut observation = completed_socketio_request();
            // Dependency activity disallows compression, but does not revoke
            // the causal evidence that the request itself completed.
            observation.dependency_activity(0);
            let close = if engine_io_close {
                observation.input(WireMessage::text("1"), 0).unwrap()
            } else {
                observation.client_close(None, String::new(), 0).unwrap()
            };
            assert_eq!(close.after, vec![2]);
            assert_eq!(close.gap_start_ms, Some(0));
            assert_eq!(close.offset_ms, 0);
            assert!(!close.compressible_gap);
            assert!(
                observation
                    .finish(EndReason::ClientClose, 0, true)
                    .unwrap()
                    .1
                    .end
                    .clean
            );
        }
    }

    #[test]
    fn close_does_not_fabricate_an_input_completion_or_reuse_one_with_pending_business() {
        let mut handshake =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        handshake.output(open(), 0).unwrap();
        assert!(handshake.pending().is_empty());
        let close = handshake.client_close(None, String::new(), 0).unwrap();
        assert!(close.after.is_empty());
        assert_eq!(close.gap_start_ms, None);

        let mut pending = completed_socketio_request();
        pending.input(WireMessage::text("422[\"ask\"]"), 1).unwrap();
        let close = pending.client_close(None, String::new(), 1).unwrap();
        assert!(close.after.is_empty());
        assert_eq!(close.gap_start_ms, None);
        assert!(
            pending
                .finish(EndReason::ClientClose, 1, true)
                .unwrap()
                .1
                .end
                .clean
        );
    }

    #[test]
    fn http_client_close_retains_pending_business_without_fabricating_a_barrier() {
        let policy = InteractionPolicy {
            stream_terminal: Some(StreamTerminal::SseEvent {
                event: "done".into(),
            }),
            ..Default::default()
        };
        let mut pending = Observation::new(Protocol::Sse, policy.clone()).unwrap();
        pending.stream_bytes(b"data: first\n\n", 1).unwrap();
        let cancel = pending.client_close(None, String::new(), 2).unwrap();
        assert!(cancel.after.is_empty());
        assert_eq!(cancel.gap_start_ms, None);
        let (_, output) = pending.finish(EndReason::ClientClose, 2, true).unwrap();
        assert!(output.end.clean);
        assert_eq!(output.end.pending, vec![0]);

        let mut completed = Observation::new(Protocol::Sse, policy.clone()).unwrap();
        completed
            .stream_bytes(b"event: done\ndata: ok\n\n", 1)
            .unwrap();
        completed.client_close(None, String::new(), 2).unwrap();
        let (input, output) = completed.finish(EndReason::ClientClose, 2, true).unwrap();
        assert!(matches!(
            input.actions[0].action,
            InputActionKind::Close { code: None, .. }
        ));
        assert_eq!(input.actions[0].after, vec![0]);
        assert_eq!(input.actions[0].gap_start_ms, Some(1));
        assert_eq!(input.actions[0].offset_ms, 2);
        assert!(!input.actions[0].compressible_gap);
        assert!(output.end.clean);
        assert_eq!(output.end.reason, EndReason::ClientClose);
        assert_eq!(
            output.end.close,
            Some(CloseObservation {
                code: None,
                reason: String::new()
            })
        );

        let mut same_tick = Observation::new(Protocol::Sse, policy.clone()).unwrap();
        same_tick
            .stream_bytes(b"event: done\ndata: ok\n\n", 0)
            .unwrap();
        let close = same_tick.client_close(None, String::new(), 0).unwrap();
        assert_eq!(close.after, vec![0]);
        assert_eq!(close.gap_start_ms, Some(0));
        assert_eq!(close.offset_ms, 0);
        assert!(!close.compressible_gap);
        assert!(
            same_tick
                .finish(EndReason::ClientClose, 0, true)
                .unwrap()
                .1
                .end
                .clean
        );

        let mut partial = Observation::new(Protocol::Sse, policy).unwrap();
        partial
            .stream_bytes(b"event: done\ndata: ok\n\ndata: unfinished", 1)
            .unwrap();
        assert!(partial.pending().is_empty());
        partial.client_close(None, String::new(), 2).unwrap();
        let (_, output) = partial.finish(EndReason::ClientClose, 2, true).unwrap();
        assert!(output.end.clean);
        assert_eq!(
            output.end.partial_message.unwrap().decode().unwrap(),
            b"data: unfinished"
        );
        assert!(partial.finish(EndReason::ServerEof, 2, true).is_err());
    }
    #[test]
    fn timing_sensitive_profile_retains_the_serial_input_interval() {
        let policy = InteractionPolicy {
            preserve_input_timing: true,
            ..Default::default()
        };
        let mut observation = Observation::new(Protocol::SocketIo, policy).unwrap();
        observation.output(open(), 0).unwrap();
        observation.input(WireMessage::text("40"), 1).unwrap();
        observation
            .output(WireMessage::text("40{\"sid\":\"namespace\"}"), 2)
            .unwrap();
        let next = observation
            .input(WireMessage::text("421[\"request\"]"), 9_000)
            .unwrap();
        assert!(!next.compressible_gap);
        assert_eq!(next.offset_ms, 9_000);
        assert_eq!(next.after, vec![1]);
    }

    fn open() -> WireMessage {
        WireMessage::text(
            "0{\"sid\":\"source\",\"upgrades\":[],\"pingInterval\":25,\"pingTimeout\":20}",
        )
    }

    #[test]
    fn source_program_retains_overlap_and_only_compresses_completed_business_gaps() {
        let policy = InteractionPolicy {
            completion: vec![EventCompletion {
                namespace: "/".into(),
                event: "ask".into(),
                completion: CompletionRule::Ack,
            }],
            ..Default::default()
        };
        let mut observation = Observation::new(Protocol::SocketIo, policy).unwrap();
        observation.output(open(), 0).unwrap();
        observation.input(WireMessage::text("40"), 1).unwrap();
        observation
            .output(WireMessage::text("40{\"sid\":\"ns\"}"), 2)
            .unwrap();
        let first = observation
            .input(WireMessage::text("421[\"ask\"]"), 20)
            .unwrap();
        assert_eq!(first.after, vec![1]);
        assert_eq!(first.gap_start_ms, Some(2));
        let overlap = observation
            .input(WireMessage::text("422[\"ask\"]"), 21)
            .unwrap();
        assert!(!overlap.compressible_gap);
        observation.output(WireMessage::text("432[]"), 22).unwrap();
        assert_eq!(observation.decision(11_000), LifecycleDecision::Continue);
        observation.output(WireMessage::text("431[]"), 23).unwrap();
        let next = observation
            .input(WireMessage::text("423[\"ask\"]"), 24)
            .unwrap();
        assert!(next.compressible_gap);
        observation.output(WireMessage::text("433[]"), 25).unwrap();
        observation
            .output(WireMessage::text("2probe"), 10_024)
            .unwrap();
        assert_eq!(
            observation.decision(10_025),
            LifecycleDecision::Close(EndReason::BusinessIdle)
        );
        assert!(
            observation
                .finish(EndReason::BusinessIdle, 10_025, true)
                .unwrap()
                .1
                .end
                .clean
        );
    }

    #[test]
    fn sse_heartbeats_cannot_extend_completed_business_idle() {
        let policy = InteractionPolicy {
            stream_terminal: Some(StreamTerminal::SseEvent {
                event: "done".into(),
            }),
            ..Default::default()
        };
        let mut observation = Observation::new(Protocol::Sse, policy).unwrap();
        observation
            .stream_bytes(b"event: done\ndata: ok\n\n", 0)
            .unwrap();
        observation.stream_bytes(b": heartbeat\n\n", 9_999).unwrap();
        assert_eq!(
            observation.decision(10_000),
            LifecycleDecision::Close(EndReason::BusinessIdle)
        );
        assert!(
            observation
                .finish(EndReason::BusinessIdle, 10_000, true)
                .unwrap()
                .1
                .events[1]
                .heartbeat
        );
    }

    #[test]
    fn dependency_work_after_completion_disables_only_the_unproven_input_gap() {
        let policy = InteractionPolicy {
            completion: vec![EventCompletion {
                namespace: "/".into(),
                event: "ask".into(),
                completion: CompletionRule::Ack,
            }],
            ..Default::default()
        };
        let mut observation = Observation::new(Protocol::SocketIo, policy).unwrap();
        observation.output(open(), 0).unwrap();
        observation.input(WireMessage::text("40"), 1).unwrap();
        observation
            .output(WireMessage::text("40{\"sid\":\"ns\"}"), 2)
            .unwrap();
        observation
            .input(WireMessage::text("421[\"ask\"]"), 3)
            .unwrap();
        observation.output(WireMessage::text("431[]"), 5).unwrap();
        observation.dependency_activity(6);
        assert!(
            !observation
                .input(WireMessage::text("422[\"ask\"]"), 50)
                .unwrap()
                .compressible_gap
        );
        observation.output(WireMessage::text("432[]"), 51).unwrap();
        observation.dependency_activity(4);
        assert!(
            observation
                .input(WireMessage::text("423[\"ask\"]"), 80)
                .unwrap()
                .compressible_gap
        );
    }

    #[test]
    fn acknowledged_id_reuse_preserves_each_observed_input_and_unfinished_business() {
        let mut observation =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        observation.output(open(), 0).unwrap();
        observation.input(WireMessage::text("40"), 0).unwrap();
        observation.output(WireMessage::text("40{}"), 0).unwrap();
        for now in 1..=3 {
            observation
                .input(WireMessage::text("4239[\"device:register\",{}]"), now)
                .unwrap();
            observation
                .output(WireMessage::text("4339[{\"success\":true}]"), now)
                .unwrap();
        }
        assert_eq!(observation.pending(), vec![2, 3, 4]);
        let (input, output) = observation.finish(EndReason::ServerEof, 4, true).unwrap();
        assert_eq!(input.actions.len(), 4);
        assert_eq!(output.end.pending, vec![2, 3, 4]);
        assert!(!output.end.clean);
    }

    #[test]
    fn server_ack_bindings_are_input_metadata_and_ambiguous_business_never_passes() {
        let mut observation =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        observation.output(open(), 0).unwrap();
        observation
            .output(WireMessage::text("4279[\"question\"]"), 1)
            .unwrap();
        let input = observation
            .input(WireMessage::text("4379[true]"), 2)
            .unwrap();
        assert_eq!(input.ack_ref.unwrap().server_event_ordinal, 1);
        observation
            .input(WireMessage::text("4280[\"unknown\"]"), 3)
            .unwrap();
        observation.output(WireMessage::text("4380[]"), 4).unwrap();
        assert!(
            !observation
                .finish(EndReason::ServerEof, 5, true)
                .unwrap()
                .1
                .end
                .clean
        );
    }
}
