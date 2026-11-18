//! Engine.IO v4 / Socket.IO v5 framing and scoped business-completion tracking.
//! This module never forwards, persists, schedules, or compares expected output.

mod ack_error;
pub mod native_receipts;

pub use ack_error::{AckFailureKind, AckObservationError};

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    model::{MessageKind, WireMessage},
    policy::{CompletionRule, InteractionPolicy},
};

pub const SERVER_REQUEST_BIT: u64 = 1 << 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Polling,
    WebSocket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineIoRequest {
    pub transport: Transport,
    pub sid: Option<String>,
}

/// The configured endpoint path is matched by the caller; this validates its transport.
pub fn classify_request(
    method: &str,
    uri: &str,
    websocket_upgrade: bool,
) -> Result<EngineIoRequest> {
    let parsed = url::Url::parse(uri)
        .or_else(|_| url::Url::parse(&format!("http://interaction.invalid{uri}")))
        .context("invalid Engine.IO request URI")?;
    let mut values = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        if matches!(key.as_ref(), "EIO" | "transport" | "sid") {
            ensure!(
                values
                    .insert(key.into_owned(), value.into_owned())
                    .is_none(),
                "duplicate Engine.IO query parameter"
            );
        }
    }
    ensure!(
        values.get("EIO").is_some_and(|value| value == "4"),
        "only Engine.IO v4 is supported"
    );
    let sid = values.remove("sid");
    if let Some(sid) = &sid {
        ensure!(
            !sid.is_empty() && sid.len() <= 1024 && !sid.chars().any(char::is_control),
            "invalid Engine.IO SID"
        );
    }
    let transport = match values.get("transport").map(String::as_str) {
        Some("polling") => {
            ensure!(
                matches!(method, "GET" | "POST") && (method != "POST" || sid.is_some()),
                "invalid Engine.IO polling method or missing SID"
            );
            Transport::Polling
        }
        Some("websocket") => {
            ensure!(
                method == "GET" && websocket_upgrade,
                "Engine.IO WebSocket transport requires a GET upgrade"
            );
            Transport::WebSocket
        }
        _ => bail!("unsupported Engine.IO transport"),
    };
    Ok(EngineIoRequest { transport, sid })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineIoOpen {
    pub sid: String,
    #[serde(default)]
    pub upgrades: Vec<String>,
    #[serde(rename = "pingInterval")]
    pub ping_interval: u64,
    #[serde(rename = "pingTimeout")]
    pub ping_timeout: u64,
    #[serde(
        rename = "maxPayload",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_payload: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineIoPacket {
    Open(EngineIoOpen),
    Close,
    Ping(String),
    Pong(String),
    Message(SocketIoPacket),
    Upgrade,
    Noop,
    Binary(Vec<u8>),
}

impl EngineIoPacket {
    pub fn is_heartbeat(&self) -> bool {
        matches!(
            self,
            Self::Ping(_) | Self::Pong(_) | Self::Noop | Self::Upgrade
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SocketIoKind {
    Connect,
    Disconnect,
    Event,
    Ack,
    ConnectError,
    BinaryEvent,
    BinaryAck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SocketIoPacket {
    pub kind: SocketIoKind,
    pub namespace: String,
    pub id: Option<u64>,
    pub data: Option<Value>,
    pub attachments: usize,
    /// Attachments preserve bytes independently of placeholder JSON and wire framing.
    pub binary: Vec<String>,
}

impl SocketIoPacket {
    pub fn encode_engine_io(&self) -> Result<String> {
        Ok(format!("4{}", encode_socket_io(self)?))
    }

    pub fn event_name(&self) -> Option<&str> {
        if matches!(self.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent) {
            self.data.as_ref()?.as_array()?.first()?.as_str()
        } else {
            None
        }
    }

    pub fn arguments(&self) -> Option<Value> {
        let data = self.data.as_ref()?.as_array()?;
        Some(Value::Array(if self.event_name().is_some() {
            data[1..].to_vec()
        } else {
            data.clone()
        }))
    }
}

pub fn decode_engine_io_text(text: &str, limit: usize) -> Result<EngineIoPacket> {
    ensure!(
        !text.is_empty() && text.len() <= limit,
        "empty or oversized Engine.IO packet"
    );
    ensure!(
        text.as_bytes()[0].is_ascii(),
        "invalid Engine.IO packet type"
    );
    let payload = &text[1..];
    Ok(match text.as_bytes()[0] {
        b'0' => {
            let value = traffic_codec_json::parse_with_limit(payload.as_bytes(), limit)
                .context("Engine.IO OPEN must be complete JSON with unique members")?;
            let open: EngineIoOpen =
                serde_json::from_value(value).context("invalid Engine.IO OPEN packet")?;
            ensure!(
                !open.sid.is_empty()
                    && open.sid.len() <= 1024
                    && open.ping_interval > 0
                    && open.ping_timeout > 0,
                "invalid Engine.IO OPEN fields"
            );
            EngineIoPacket::Open(open)
        }
        b'1' => {
            ensure!(payload.is_empty(), "invalid Engine.IO CLOSE payload");
            EngineIoPacket::Close
        }
        b'2' => EngineIoPacket::Ping(payload.to_owned()),
        b'3' => EngineIoPacket::Pong(payload.to_owned()),
        b'4' => EngineIoPacket::Message(decode_socket_io(payload, limit)?),
        b'5' => {
            ensure!(payload.is_empty(), "invalid Engine.IO UPGRADE payload");
            EngineIoPacket::Upgrade
        }
        b'6' => {
            ensure!(payload.is_empty(), "invalid Engine.IO NOOP payload");
            EngineIoPacket::Noop
        }
        b'b' => EngineIoPacket::Binary(
            STANDARD
                .decode(payload)
                .context("invalid Engine.IO polling binary packet")?,
        ),
        _ => bail!("unknown Engine.IO packet type"),
    })
}

pub fn decode_polling_payload(bytes: &[u8], limit: usize) -> Result<Vec<EngineIoPacket>> {
    std::str::from_utf8(bytes)
        .context("Engine.IO polling body is not UTF-8")?
        .split('\u{1e}')
        .map(|packet| decode_engine_io_text(packet, limit))
        .collect()
}

pub fn decode_socket_io(text: &str, limit: usize) -> Result<SocketIoPacket> {
    ensure!(
        !text.is_empty() && text.len() <= limit,
        "empty or oversized Socket.IO packet"
    );
    ensure!(
        text.as_bytes()[0].is_ascii(),
        "invalid Socket.IO packet type"
    );
    let kind = match text.as_bytes()[0] {
        b'0' => SocketIoKind::Connect,
        b'1' => SocketIoKind::Disconnect,
        b'2' => SocketIoKind::Event,
        b'3' => SocketIoKind::Ack,
        b'4' => SocketIoKind::ConnectError,
        b'5' => SocketIoKind::BinaryEvent,
        b'6' => SocketIoKind::BinaryAck,
        _ => bail!("unknown Socket.IO packet type"),
    };
    let mut rest = &text[1..];
    let attachments = if matches!(kind, SocketIoKind::BinaryEvent | SocketIoKind::BinaryAck) {
        let (count, tail) = rest
            .split_once('-')
            .context("binary Socket.IO packet lacks attachment count")?;
        ensure!(
            !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid Socket.IO attachment count"
        );
        let count: usize = count
            .parse()
            .context("Socket.IO attachment count overflow")?;
        ensure!(
            count > 0 && count <= 1024,
            "Socket.IO attachment count exceeds limit"
        );
        rest = tail;
        count
    } else {
        0
    };
    let namespace = if rest.starts_with('/') {
        let (namespace, tail) = rest.split_once(',').unwrap_or((rest, ""));
        ensure!(
            namespace.len() <= 1024 && !namespace.chars().any(char::is_control),
            "invalid Socket.IO namespace"
        );
        rest = tail;
        namespace.to_owned()
    } else {
        "/".to_owned()
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let id = if digits > 0 {
        let id = rest[..digits]
            .parse()
            .context("Socket.IO ACK identity overflow")?;
        rest = &rest[digits..];
        Some(id)
    } else {
        None
    };
    let data: Option<Value> = if rest.is_empty() {
        None
    } else {
        Some(
            traffic_codec_json::parse_with_limit(rest.as_bytes(), limit)
                .context("Socket.IO payload must be complete JSON with unique members")?,
        )
    };
    match kind {
        SocketIoKind::Connect => ensure!(
            id.is_none() && data.as_ref().is_none_or(Value::is_object),
            "invalid Socket.IO CONNECT payload"
        ),
        SocketIoKind::Disconnect => ensure!(
            id.is_none() && data.is_none(),
            "invalid Socket.IO DISCONNECT payload"
        ),
        SocketIoKind::Event | SocketIoKind::BinaryEvent => ensure!(
            data.as_ref()
                .and_then(Value::as_array)
                .and_then(|array| array.first())
                .and_then(Value::as_str)
                .is_some_and(|event| !event.is_empty()),
            "Socket.IO EVENT requires an event-name array"
        ),
        SocketIoKind::Ack | SocketIoKind::BinaryAck => ensure!(
            id.is_some() && data.as_ref().is_some_and(Value::is_array),
            "Socket.IO ACK requires an ID and array"
        ),
        SocketIoKind::ConnectError => ensure!(
            id.is_none() && data.is_some(),
            "invalid Socket.IO CONNECT_ERROR payload"
        ),
    }
    if attachments > 0 {
        validate_placeholders(data.as_ref().unwrap_or(&Value::Null), attachments)?;
    }
    Ok(SocketIoPacket {
        kind,
        namespace,
        id,
        data,
        attachments,
        binary: Vec::new(),
    })
}

fn validate_placeholders(value: &Value, count: usize) -> Result<()> {
    match value {
        Value::Object(object) if object.get("_placeholder") == Some(&Value::Bool(true)) => {
            ensure!(
                object
                    .get("num")
                    .and_then(Value::as_u64)
                    .is_some_and(|index| index < count as u64),
                "invalid Socket.IO binary placeholder"
            );
        }
        Value::Object(object) => {
            for value in object.values() {
                validate_placeholders(value, count)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                validate_placeholders(value, count)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn encode_socket_io(packet: &SocketIoPacket) -> Result<String> {
    let kind = match packet.kind {
        SocketIoKind::Connect => '0',
        SocketIoKind::Disconnect => '1',
        SocketIoKind::Event => '2',
        SocketIoKind::Ack => '3',
        SocketIoKind::ConnectError => '4',
        SocketIoKind::BinaryEvent => '5',
        SocketIoKind::BinaryAck => '6',
    };
    let mut text = kind.to_string();
    if matches!(
        packet.kind,
        SocketIoKind::BinaryEvent | SocketIoKind::BinaryAck
    ) {
        text.push_str(&format!("{}-", packet.attachments));
    }
    if packet.namespace != "/" {
        text.push_str(&packet.namespace);
        text.push(',');
    }
    if let Some(id) = packet.id {
        text.push_str(&id.to_string());
    }
    if let Some(data) = &packet.data {
        text.push_str(&serde_json::to_string(data)?);
    }
    Ok(text)
}

pub struct SocketIoDecoder {
    limit: usize,
    pending: Option<SocketIoPacket>,
    pending_bytes: usize,
}

impl SocketIoDecoder {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            pending: None,
            pending_bytes: 0,
        }
    }

    pub fn has_pending_binary(&self) -> bool {
        self.pending.is_some()
    }

    pub fn push(&mut self, message: &WireMessage) -> Result<Vec<EngineIoPacket>> {
        let packets = match message.kind {
            MessageKind::Text => decode_polling_payload(message.data.as_bytes(), self.limit)?,
            MessageKind::Binary => vec![EngineIoPacket::Binary(message.decode()?)],
        };
        let mut complete = Vec::new();
        for packet in packets {
            match packet {
                EngineIoPacket::Binary(bytes) => {
                    let pending = self
                        .pending
                        .as_mut()
                        .context("Socket.IO attachment without a binary header")?;
                    self.pending_bytes = self.pending_bytes.saturating_add(bytes.len());
                    ensure!(
                        self.pending_bytes <= self.limit,
                        "Socket.IO binary message exceeds configured limit"
                    );
                    pending.binary.push(STANDARD.encode(bytes));
                    if pending.binary.len() == pending.attachments {
                        complete.push(EngineIoPacket::Message(self.pending.take().unwrap()));
                        self.pending_bytes = 0;
                    }
                }
                EngineIoPacket::Message(packet) if packet.attachments > 0 => {
                    ensure!(
                        self.pending.is_none(),
                        "overlapping Socket.IO binary messages"
                    );
                    self.pending_bytes = encode_socket_io(&packet)?.len().saturating_add(1);
                    self.pending = Some(packet);
                }
                EngineIoPacket::Message(_) if self.pending.is_some() => {
                    bail!("Socket.IO message interrupted binary attachments")
                }
                packet => complete.push(packet),
            }
        }
        Ok(complete)
    }

    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.pending.is_none(),
            "Socket.IO stream ended before binary attachments completed"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompletionUpdate {
    pub started: Vec<u64>,
    pub completed: Vec<u64>,
    pub business: bool,
}

#[derive(Debug)]
struct Pending {
    namespace: String,
    ack: Option<u64>,
    arguments: Value,
    rule: Option<CompletionRule>,
    connecting: bool,
    acked: bool,
    terminal: bool,
}

pub struct CompletionTracker {
    policy: InteractionPolicy,
    pending: BTreeMap<u64, Pending>,
    server_pending: BTreeMap<(String, u64), u64>,
    server_requests: u64,
}

impl CompletionTracker {
    pub fn new(policy: InteractionPolicy) -> Self {
        Self {
            policy,
            pending: BTreeMap::new(),
            server_pending: BTreeMap::new(),
            server_requests: 0,
        }
    }

    pub fn pending(&self) -> Vec<u64> {
        let mut pending: Vec<_> = self
            .pending
            .keys()
            .copied()
            .chain(self.server_pending.values().copied())
            .collect();
        pending.sort_unstable();
        pending
    }

    pub fn observe_client(
        &mut self,
        sequence: u64,
        packet: &SocketIoPacket,
        _now_ms: u64,
    ) -> Result<CompletionUpdate> {
        ensure!(
            sequence < SERVER_REQUEST_BIT,
            "client input sequence uses reserved server-request bit"
        );
        let mut update = CompletionUpdate {
            business: true,
            ..Default::default()
        };
        match packet.kind {
            SocketIoKind::Connect | SocketIoKind::Event | SocketIoKind::BinaryEvent => {
                ensure!(
                    !self.pending.contains_key(&sequence),
                    "duplicate Socket.IO input identity"
                );
                // Receiving an ACK releases its wire identity even when a
                // terminal event or an unknown business lifetime remains open.
                if let Some(id) = packet.id
                    && self.pending.values().any(|pending| {
                        pending.namespace == packet.namespace
                            && pending.ack == Some(id)
                            && !pending.acked
                    })
                {
                    return Err(AckObservationError::new(
                        AckFailureKind::ClientIdentityInFlight,
                        id,
                    )
                    .into());
                }
                let connecting = packet.kind == SocketIoKind::Connect;
                ensure!(
                    !connecting
                        || !self
                            .pending
                            .values()
                            .any(|pending| pending.connecting
                                && pending.namespace == packet.namespace),
                    "duplicate pending namespace connection"
                );
                let rule = packet
                    .event_name()
                    .and_then(|event| self.policy.completion_for(&packet.namespace, event))
                    .cloned();
                if matches!(
                    rule,
                    Some(CompletionRule::Ack)
                        | Some(CompletionRule::TerminalEvent {
                            require_ack: true,
                            ..
                        })
                ) {
                    ensure!(
                        packet.id.is_some(),
                        "configured Socket.IO ACK completion requires an input ACK ID"
                    );
                }
                let arguments = packet.arguments().unwrap_or(Value::Null);
                if let Some(CompletionRule::TerminalEvent {
                    correlation: Some(correlation),
                    ..
                }) = &rule
                {
                    ensure!(
                        arguments.pointer(&correlation.input_pointer).is_some(),
                        "Socket.IO input lacks configured completion correlation"
                    );
                }
                self.pending.insert(
                    sequence,
                    Pending {
                        namespace: packet.namespace.clone(),
                        ack: packet.id,
                        arguments,
                        rule,
                        connecting,
                        acked: false,
                        terminal: false,
                    },
                );
                update.started.push(sequence);
            }
            SocketIoKind::Ack | SocketIoKind::BinaryAck => {
                let key = (
                    packet.namespace.clone(),
                    packet.id.context("client ACK lacks identity")?,
                );
                update
                    .completed
                    .push(self.server_pending.remove(&key).ok_or_else(|| {
                        AckObservationError::new(AckFailureKind::ClientAckNotPending, key.1)
                    })?);
            }
            SocketIoKind::Disconnect => {}
            SocketIoKind::ConnectError => bail!("client cannot send CONNECT_ERROR"),
        }
        Ok(update)
    }

    pub fn observe_server(
        &mut self,
        packet: &SocketIoPacket,
        _now_ms: u64,
    ) -> Result<CompletionUpdate> {
        let mut update = CompletionUpdate {
            business: true,
            ..Default::default()
        };
        match packet.kind {
            SocketIoKind::Connect | SocketIoKind::ConnectError => {
                let ids: Vec<_> = self
                    .pending
                    .iter()
                    .filter(|(_, pending)| {
                        pending.connecting && pending.namespace == packet.namespace
                    })
                    .map(|(id, _)| *id)
                    .collect();
                for id in ids {
                    self.pending.remove(&id);
                    update.completed.push(id);
                }
            }
            SocketIoKind::Ack | SocketIoKind::BinaryAck => {
                let id = packet.id.context("server ACK lacks identity")?;
                let matched = self
                    .pending
                    .iter_mut()
                    .find(|(_, pending)| {
                        pending.namespace == packet.namespace
                            && pending.ack == Some(id)
                            && !pending.acked
                    })
                    .ok_or_else(|| {
                        AckObservationError::new(AckFailureKind::ServerAckNotPending, id)
                    })?;
                matched.1.acked = true;
                if is_complete(matched.1) {
                    let sequence = *matched.0;
                    self.pending.remove(&sequence);
                    update.completed.push(sequence);
                }
            }
            SocketIoKind::Event | SocketIoKind::BinaryEvent => {
                let event = packet.event_name().context("server EVENT lacks name")?;
                let args = packet.arguments().unwrap_or(Value::Null);
                let candidates: Vec<_> = self
                    .pending
                    .iter()
                    .filter(|(_, pending)| {
                        if pending.namespace != packet.namespace {
                            return false;
                        }
                        match &pending.rule {
                            Some(CompletionRule::TerminalEvent {
                                event: terminal,
                                correlation,
                                ..
                            }) if terminal == event => {
                                correlation.as_ref().is_none_or(|correlation| {
                                    pending
                                        .arguments
                                        .pointer(&correlation.input_pointer)
                                        .zip(args.pointer(&correlation.output_pointer))
                                        .is_some_and(|(input, output)| input == output)
                                })
                            }
                            _ => false,
                        }
                    })
                    .map(|(id, _)| *id)
                    .collect();
                ensure!(
                    candidates.len() <= 1,
                    "ambiguous Socket.IO terminal event correlation"
                );
                for id in candidates {
                    let pending = self.pending.get_mut(&id).unwrap();
                    pending.terminal = true;
                    if is_complete(pending) {
                        self.pending.remove(&id);
                        update.completed.push(id);
                    }
                }
                if let Some(id) = packet.id {
                    let key = (packet.namespace.clone(), id);
                    if self.server_pending.contains_key(&key) {
                        return Err(AckObservationError::new(
                            AckFailureKind::ServerIdentityInFlight,
                            id,
                        )
                        .into());
                    }
                    ensure!(
                        self.server_requests < SERVER_REQUEST_BIT - 1,
                        "server request identity overflow"
                    );
                    self.server_requests += 1;
                    let request = SERVER_REQUEST_BIT | self.server_requests;
                    self.server_pending.insert(key, request);
                    update.started.push(request);
                }
            }
            SocketIoKind::Disconnect => {}
        }
        Ok(update)
    }
}

fn is_complete(pending: &Pending) -> bool {
    match &pending.rule {
        Some(CompletionRule::Ack) => pending.acked,
        Some(CompletionRule::TerminalEvent { require_ack, .. }) => {
            pending.terminal && (!require_ack || pending.acked)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests;

pub mod delivery_windows;
