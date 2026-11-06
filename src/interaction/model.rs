//! Portable input programs and independently observed output evidence.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::policy::InteractionPolicy;

pub const TRANSCRIPT_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Sse,
    Ndjson,
    RawStream,
    WebSocket,
    SocketIo,
}

/// Response streams await a result; subscriptions observe a bounded idle window.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpStreamMode {
    #[default]
    Response,
    Subscription,
}

impl HttpStreamMode {
    fn is_response(&self) -> bool {
        *self == Self::Response
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Text,
    Binary,
}

/// Text is UTF-8; binary data is canonical base64. Never infer the encoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WireMessage {
    pub kind: MessageKind,
    pub data: String,
}

impl WireMessage {
    pub fn text(data: impl Into<String>) -> Self {
        Self {
            kind: MessageKind::Text,
            data: data.into(),
        }
    }

    pub fn binary(data: &[u8]) -> Self {
        Self {
            kind: MessageKind::Binary,
            data: STANDARD.encode(data),
        }
    }

    pub fn decode(&self) -> Result<Vec<u8>> {
        match self.kind {
            MessageKind::Text => Ok(self.data.as_bytes().to_vec()),
            MessageKind::Binary => STANDARD
                .decode(&self.data)
                .context("invalid interaction binary base64"),
        }
    }
}

/// Only this program is visible to the request driver. Expected output is absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputTranscript {
    pub version: u8,
    pub protocol: Protocol,
    pub policy: InteractionPolicy,
    #[serde(default, skip_serializing_if = "HttpStreamMode::is_response")]
    pub http_stream_mode: HttpStreamMode,
    /// Explicit client Engine.IO heartbeat responses. Absence retains legacy
    /// automatic PONG behavior; an empty program deliberately sends no replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_io_heartbeat: Option<SocketIoHeartbeats>,
    #[serde(default)]
    pub actions: Vec<InputAction>,
}

impl InputTranscript {
    pub fn new(protocol: Protocol, policy: InteractionPolicy) -> Self {
        Self {
            version: TRANSCRIPT_VERSION,
            protocol,
            policy,
            http_stream_mode: HttpStreamMode::Response,
            socket_io_heartbeat: None,
            actions: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == TRANSCRIPT_VERSION,
            "unsupported interaction input version {}",
            self.version
        );
        self.policy.validate()?;
        ensure!(
            self.http_stream_mode != HttpStreamMode::Subscription
                || (self.protocol == Protocol::Sse && self.policy.stream_terminal.is_none()),
            "HTTP subscription mode requires SSE without a response terminal rule"
        );
        let mut previous = None;
        let mut seen = std::collections::BTreeSet::new();
        if matches!(
            self.protocol,
            Protocol::Sse | Protocol::Ndjson | Protocol::RawStream
        ) {
            // The initial HTTP request is implicit in the request artifact.
            // A later client close can depend on its actual business completion.
            seen.insert(0);
        }
        let mut offset = 0;
        let mut precise_offset = None;
        for (index, action) in self.actions.iter().enumerate() {
            ensure!(
                self.http_stream_mode != HttpStreamMode::Subscription || action.after.is_empty(),
                "HTTP subscription close cannot depend on a response completion"
            );
            ensure!(
                !self.policy.preserve_input_timing || !action.compressible_gap,
                "timing-preserving interaction cannot contain compressed input gaps"
            );
            ensure!(
                action.sequence < (1 << 63),
                "interaction input uses a reserved request identity"
            );
            ensure!(
                previous.is_none_or(|sequence| action.sequence > sequence),
                "interaction input sequences must strictly increase"
            );
            ensure!(
                action.offset_ms >= offset,
                "interaction input offsets must not decrease"
            );
            if let Some(us) = action.offset_us {
                ensure!(
                    us / 1_000 == action.offset_ms
                        && precise_offset.is_none_or(|previous| us >= previous),
                    "interaction input microsecond offsets must agree with milliseconds and not decrease"
                );
                precise_offset = Some(us);
            }
            ensure!(
                action.after.iter().all(|sequence| seen.contains(sequence)),
                "interaction completion barriers must reference previous inputs"
            );
            ensure!(
                !action.compressible_gap || !action.after.is_empty(),
                "compressed input gap requires an explicit completion barrier"
            );
            ensure!(
                !action.compressible_gap
                    || action.gap_start_ms.is_some_and(|at| at <= action.offset_ms),
                "compressed input gap requires its Source completion time"
            );
            if let InputActionKind::Message { message } = &action.action {
                ensure!(
                    message.decode()?.len() <= self.policy.max_message_bytes,
                    "interaction input message exceeds configured limit"
                );
            }
            if matches!(action.action, InputActionKind::TransportEnd { .. }) {
                ensure!(
                    matches!(self.protocol, Protocol::WebSocket | Protocol::SocketIo),
                    "client transport termination requires a WebSocket interaction"
                );
                ensure!(
                    index + 1 == self.actions.len(),
                    "client transport termination must be the final input"
                );
                ensure!(
                    action.after.is_empty()
                        && !action.compressible_gap
                        && action.gap_start_ms.is_none()
                        && action.ack_ref.is_none(),
                    "client transport termination cannot depend on business completion, ACKs or compressed gaps"
                );
                ensure!(
                    self.protocol != Protocol::SocketIo || self.socket_io_heartbeat.is_some(),
                    "client transport termination requires explicit recorded Socket.IO heartbeat behavior"
                );
            }
            previous = Some(action.sequence);
            seen.insert(action.sequence);
            offset = action.offset_ms;
        }
        super::heartbeat::validate(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SocketIoHeartbeats {
    pub responses: Vec<HeartbeatResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatResponse {
    pub input_sequence: u64,
    pub ping_ordinal: u64,
    pub delay_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputAction {
    pub sequence: u64,
    pub offset_ms: u64,
    /// Precise elapsed time on the same recording epoch as offset_ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset_us: Option<u64>,
    /// Completed input sequences, selected from Source observations when recording.
    /// HTTP streams use implicit sequence 0 for their initial request.
    #[serde(default)]
    pub after: Vec<u64>,
    #[serde(default)]
    pub compressible_gap: bool,
    /// Source completion time for the safe gap; raw Source offsets remain intact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_start_ms: Option<u64>,
    /// A client ACK refers to a live server event, never to its recorded ACK ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_ref: Option<AckReference>,
    pub action: InputActionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AckReference {
    pub namespace: String,
    pub server_event_ordinal: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputActionKind {
    /// One Engine.IO packet, delivered over either polling or WebSocket.
    Message {
        message: WireMessage,
    },
    /// Upgrade an existing Engine.IO polling session; its live SID is rebound.
    Upgrade {
        uri: String,
        #[serde(default)]
        headers: BTreeMap<String, Vec<String>>,
    },
    Close {
        code: Option<u16>,
        reason: String,
    },
    /// Actual client TCP termination; it does not encode a WebSocket Close.
    TransportEnd {
        end: ClientTransportEnd,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientTransportEnd {
    Eof,
    Reset,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputObservation {
    pub version: u8,
    pub protocol: Protocol,
    pub events: Vec<OutputEvent>,
    pub end: EndObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputEvent {
    pub sequence: u64,
    pub offset_ms: u64,
    pub message: WireMessage,
    /// Protocol control traffic is retained but cannot extend business idle.
    #[serde(default)]
    pub heartbeat: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndObservation {
    pub reason: EndReason,
    pub offset_ms: u64,
    #[serde(default)]
    pub pending: Vec<u64>,
    /// The observed lifecycle ended without capture/transport corruption.
    /// An observed peer close may retain pending business identities.
    pub clean: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_predecessor: Option<MissingPredecessor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_timeout: Option<DispatchTimeout>,
    /// Exact unfinished framed-message bytes observed at an explicit client close.
    /// This suffix is not a completed business message or a successful EOF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_message: Option<WireMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close: Option<CloseObservation>,
}

impl EndObservation {
    /// An observed client transport end while recorded business work is pending.
    pub(crate) fn interrupted_by_client(&self) -> bool {
        self.clean && self.reason == EndReason::ClientTransportEnd && !self.pending.is_empty()
    }

    pub(crate) fn observes_close_tail(&self, protocol: Protocol) -> bool {
        self.interrupted_by_client()
            || (protocol == Protocol::SocketIo
                && self.clean
                && !self.pending.is_empty()
                && matches!(self.reason, EndReason::ClientClose | EndReason::ServerEof))
    }
}

pub(crate) const CLIENT_ABORT_QUIET: std::time::Duration = std::time::Duration::from_secs(15);
pub(crate) const CLIENT_ABORT_LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloseObservation {
    pub code: Option<u16>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MissingPredecessor {
    pub input_sequence: u64,
    pub output_sequence: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchTimeout {
    pub input_sequence: u64,
    pub stage: DispatchStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unadmitted_request: Option<DispatchDependency>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DispatchStage {
    Prerequisites,
    Timing,
    Send,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum DispatchDependency {
    Redis {
        connection_id: uuid::Uuid,
        sequence: u64,
    },
    Mysql {
        connection_id: uuid::Uuid,
        sequence: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    ServerEof,
    FastHeartbeatTailSkipped,
    ClientClose,
    ClientTransportEnd,
    BusinessIdle,
    RequestTimeout,
    DependencyFailure,
    MissingPredecessor,
    DispatchTimeout,
    MaxDuration,
    TransportError,
    ProtocolError,
    BudgetExceeded,
    CleanupTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socketio_close_tail_requires_a_clean_close_with_pending_work() {
        for reason in [
            EndReason::ServerEof,
            EndReason::ClientClose,
            EndReason::ClientTransportEnd,
        ] {
            let mut end = EndObservation {
                reason,
                offset_ms: 0,
                pending: vec![1],
                clean: true,
                missing_predecessor: None,
                dispatch_timeout: None,
                partial_message: None,
                close: None,
            };
            assert!(end.observes_close_tail(Protocol::SocketIo));
            assert_eq!(
                end.observes_close_tail(Protocol::WebSocket),
                reason == EndReason::ClientTransportEnd
            );
            end.clean = false;
            assert!(!end.observes_close_tail(Protocol::SocketIo));
            end.clean = true;
            end.pending.clear();
            assert!(!end.observes_close_tail(Protocol::SocketIo));
        }
    }
}
