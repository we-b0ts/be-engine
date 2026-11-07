//! Source-only proof for a subscription-driven Socket.IO stream.
use super::*;
use crate::interaction::socketio::SocketIoPacket;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(crate) struct Passive {
    pub(crate) outputs: Vec<[u8; 32]>,
    pub(crate) output_count: usize,
    pub(crate) last_output_ms: u64,
    pub(crate) end_ms: u64,
}

pub(crate) fn event_fingerprint(namespace: &str, name: &str, args: &[Value]) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(&(namespace, name, args)).expect("serialize event")).into()
}

impl Passive {
    pub(crate) fn input_namespace(input: &InputTranscript) -> Option<String> {
        let packet = |action: &crate::interaction::model::InputAction| {
            let InputActionKind::Message { message } = &action.action else {
                return None;
            };
            (message.kind == MessageKind::Text)
                .then(|| decode_engine_io_text(&message.data, input.policy.max_message_bytes).ok())
                .flatten()
        };
        let (first, rest) = input.actions.split_first()?;
        let EngineIoPacket::Message(connect) = packet(first)? else {
            return None;
        };
        (connect.kind == SocketIoKind::Connect
            && rest
                .iter()
                .all(|action| matches!(packet(action), Some(EngineIoPacket::Pong(_)))))
        .then_some(connect.namespace)
    }

    pub(crate) fn recognize(input: &InputTranscript, output: &OutputObservation) -> Option<Self> {
        let namespace = Self::input_namespace(input)?;
        let (end_ms, _) = timeout(input, output)?;
        if !output.end.pending.is_empty() {
            return None;
        }
        let mut events = output.events.iter().filter(|event| !event.heartbeat);
        let mut decoder = SocketIoDecoder::new(input.policy.max_message_bytes);
        let mut packets = |event: &crate::interaction::model::OutputEvent| {
            let [packet] = decoder.push(&event.message).ok()?.try_into().ok()?;
            Some(packet)
        };
        if !matches!(packets(events.next()?)?, EngineIoPacket::Open(_))
            || !matches!(packets(events.next()?)?, EngineIoPacket::Message(packet)
                if packet.kind == SocketIoKind::Connect && packet.namespace == namespace)
        {
            return None;
        }
        let mut outputs = Vec::new();
        let mut last_output_ms = 0;
        for event in events {
            let EngineIoPacket::Message(SocketIoPacket {
                kind: SocketIoKind::Event,
                namespace: actual,
                data: Some(Value::Array(data)),
                id: None,
                ..
            }) = packets(event)?
            else {
                return None;
            };
            let (name, args) = data.split_first()?;
            if actual != namespace {
                return None;
            }
            outputs.push(event_fingerprint(&namespace, name.as_str()?, args));
            last_output_ms = event.offset_ms;
        }
        decoder.finish().ok()?;
        (!outputs.is_empty() && last_output_ms < end_ms).then(|| Self {
            output_count: outputs.len() + 2,
            outputs,
            last_output_ms,
            end_ms,
        })
    }
}
