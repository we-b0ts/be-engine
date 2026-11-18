//! Source-only proof for a subscription-driven Socket.IO stream.
use super::*;
use crate::interaction::socketio::SocketIoPacket;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct Passive {
    pub outputs: Vec<(u64, [u8; 32])>,
    pub output_count: usize,
    pub setup_finished_ms: u64,
    pub end_ms: u64,
}

struct Setup {
    namespace: String,
    events: BTreeMap<u64, (u64, u64)>,
}

pub fn event_fingerprint(namespace: &str, name: &str, args: &[Value]) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(&(namespace, name, args)).expect("serialize event")).into()
}

impl Passive {
    pub fn input_namespace(input: &InputTranscript) -> Option<String> {
        Some(Self::setup(input)?.namespace)
    }

    fn setup(input: &InputTranscript) -> Option<Setup> {
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
        if connect.kind != SocketIoKind::Connect {
            return None;
        }
        let mut events = BTreeMap::new();
        for action in rest {
            match packet(action)? {
                EngineIoPacket::Pong(_) => {}
                EngineIoPacket::Message(event)
                    if event.kind == SocketIoKind::Event
                        && event.namespace == connect.namespace
                        && event.attachments == 0
                        && action.ack_ref.is_none()
                        && !matches!(
                            event.event_name().and_then(|name| {
                                input.policy.completion_for(&event.namespace, name)
                            }),
                            Some(crate::interaction::policy::CompletionRule::TerminalEvent { .. })
                        ) =>
                {
                    if events
                        .insert(event.id?, (action.sequence, action.offset_ms))
                        .is_some()
                    {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        Some(Setup {
            namespace: connect.namespace,
            events,
        })
    }

    pub fn recognize(input: &InputTranscript, output: &OutputObservation) -> Option<Self> {
        let Setup {
            namespace,
            events: mut setup,
        } = Self::setup(input)?;
        let (end_ms, _) = timeout(input, output)?;
        let output_count = output
            .events
            .iter()
            .filter(|event| !event.heartbeat)
            .count();
        let mut events = output.events.iter().filter(|event| !event.heartbeat);
        let mut decoder = SocketIoDecoder::new(input.policy.max_message_bytes);
        let mut packets = |event: &crate::interaction::model::OutputEvent| {
            let [packet] = decoder.push(&event.message).ok()?.try_into().ok()?;
            Some(packet)
        };
        if !matches!(packets(events.next()?)?, EngineIoPacket::Open(_)) {
            return None;
        }
        let connected = events.next()?;
        if !matches!(packets(connected)?, EngineIoPacket::Message(packet)
                if packet.kind == SocketIoKind::Connect && packet.namespace == namespace)
        {
            return None;
        }
        let mut acknowledged = BTreeSet::new();
        let mut setup_finished_ms = connected.offset_ms;
        let mut outputs = Vec::new();
        for event in events {
            let EngineIoPacket::Message(packet) = packets(event)? else {
                return None;
            };
            if packet.namespace != namespace {
                return None;
            }
            match packet {
                SocketIoPacket {
                    kind: SocketIoKind::Ack,
                    id: Some(id),
                    ..
                } if outputs.is_empty() => {
                    let (sequence, sent_at) = setup.remove(&id)?;
                    if sent_at <= connected.offset_ms || sent_at >= event.offset_ms {
                        return None;
                    }
                    acknowledged.insert(sequence);
                    setup_finished_ms = event.offset_ms;
                }
                SocketIoPacket {
                    kind: SocketIoKind::Event,
                    data: Some(Value::Array(data)),
                    id: None,
                    ..
                } if setup.is_empty() => {
                    let (name, args) = data.split_first()?;
                    outputs.push((
                        event.offset_ms,
                        event_fingerprint(&namespace, name.as_str()?, args),
                    ));
                }
                _ => return None,
            }
        }
        decoder.finish().ok()?;
        let (first_output_ms, _) = outputs.first()?;
        let (last_output_ms, _) = outputs.last()?;
        (*first_output_ms > setup_finished_ms
            && *last_output_ms < end_ms
            && output
                .end
                .pending
                .iter()
                .all(|id| acknowledged.contains(id)))
        .then_some(Self {
            output_count,
            outputs,
            setup_finished_ms,
            end_ms,
        })
    }
}
