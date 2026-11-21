//! Source Socket.IO namespaces, completion fences and finite delivery windows.
//! The host supplies authenticated metadata and lazily loads original outputs.
use crate::interaction::{
    model::{InputActionKind, InputTranscript, Protocol},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
mod checkpoints;

pub struct Window {
    pub case: String,
    pub start: Option<DateTime<Utc>>,
    pub connected_after: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub namespaces: BTreeSet<String>,
    pub projectable: bool,
    pub inputs: Vec<InputClock>,
    fences: Vec<Fence>,
    pub selected: bool,
}

struct TrackedInputs {
    acknowledgements: Vec<InputClock>,
    ack_ids: BTreeMap<u64, (u64, u64)>,
    unacknowledged: Vec<(u64, u64)>,
    close_ms: Option<u64>,
}

pub struct InputClock {
    pub sequence: u64,
    pub offset_ms: u64,
    pub offset_us: Option<u64>,
}

struct Fence {
    from_ms: u64,
    resume_after_ms: Option<u64>,
}

impl Window {
    pub fn delivery_cutoff(&self, offset: chrono::TimeDelta) -> Option<chrono::TimeDelta> {
        let end = self.end? - self.start?;
        let offset_ms = u64::try_from(offset.num_milliseconds()).ok()?;
        for fence in &self.fences {
            if offset_ms < fence.from_ms {
                let boundary = chrono::TimeDelta::try_milliseconds(fence.from_ms.try_into().ok()?)?;
                return Some(end.min(boundary));
            }
            if fence
                .resume_after_ms
                .is_none_or(|resume| offset_ms <= resume)
            {
                return None;
            }
        }
        Some(end)
    }
}

#[derive(Deserialize)]
pub struct InputMetadata {
    timestamp: Option<DateTime<Utc>>,
    interaction: Option<Value>,
}

impl InputMetadata {
    pub fn supports_delivery_windows(&self) -> bool {
        self.interaction
            .as_ref()
            .is_some_and(|input| input["protocol"] == "socket_io")
    }
}
#[derive(Deserialize)]
pub struct OutputMetadata {
    duration_ms: Option<u64>,
    interaction: Option<Completion>,
}
#[derive(Deserialize)]
struct Completion {
    version: Option<u8>,
    protocol: Option<Protocol>,
    end: Option<End>,
}
#[derive(Deserialize)]
struct End {
    clean: Option<bool>,
    reason: Option<crate::interaction::model::EndReason>,
    offset_ms: Option<u64>,
}

impl Window {
    pub fn prepare(
        case: String,
        selected: bool,
        complete: bool,
        request: InputMetadata,
        response: Option<OutputMetadata>,
        read_outputs: impl FnOnce() -> Result<Option<Value>>,
    ) -> Result<Option<Self>> {
        let Some(interaction) = request.interaction.filter(|v| v["protocol"] == "socket_io") else {
            return Ok(None);
        };
        let start = request.timestamp;
        let input = serde_json::from_value::<InputTranscript>(interaction)
            .ok()
            .filter(|input| input.validate().is_ok());
        let namespaces = input.as_ref().map(namespaces).unwrap_or_default();
        let completion = response.as_ref().and_then(|r| r.interaction.as_ref());
        let end = completion.and_then(|c| c.end.as_ref());
        let elapsed = end
            .and_then(|end| end.offset_ms)
            .or_else(|| response.as_ref().and_then(|r| r.duration_ms));
        let transport_end = input
            .as_ref()
            .and_then(|input| input.actions.last())
            .filter(|action| matches!(action.action, InputActionKind::TransportEnd { .. }))
            .map(|action| action.offset_ms);
        // Source cleanup can finish after a real client FIN/RST. That cleanup
        // is dependency evidence, not a longer external input delivery window.
        let window_elapsed = elapsed.map(|end| transport_end.map_or(end, |at| at.min(end)));
        let closed_at = window_elapsed
            .and_then(|ms| i64::try_from(ms).ok())
            .and_then(|ms| {
                start
                    .and_then(|start| start.checked_add_signed(chrono::TimeDelta::milliseconds(ms)))
            });
        let clean = completion.is_some_and(|c| {
            c.version == Some(crate::interaction::model::TRANSCRIPT_VERSION)
                && c.protocol == Some(Protocol::SocketIo)
        }) && end.is_some_and(|end| {
            end.clean == Some(true)
                && matches!(
                    end.reason,
                    Some(
                        crate::interaction::model::EndReason::BusinessIdle
                            | crate::interaction::model::EndReason::ClientClose
                            | crate::interaction::model::EndReason::ServerEof
                            | crate::interaction::model::EndReason::ClientTransportEnd
                    )
                )
        }) && ((end.and_then(|end| end.reason)
            == Some(crate::interaction::model::EndReason::ClientTransportEnd))
            == transport_end.is_some());
        let inputs = input.as_ref().and_then(tracked_inputs);
        let projectable = complete
            && clean
            && start.zip(closed_at).is_some_and(|(start, end)| end > start)
            && input.as_ref().is_some_and(|input| {
                inputs.is_some()
                    && namespaces.len() == 1
                    && elapsed.is_some_and(|end| {
                        input.actions.last().is_some_and(|action| {
                            action.offset_ms < end
                                || action.offset_ms == end && transport_end.is_some()
                        }) && end <= input.policy.max_duration_ms
                    })
            });
        let fences = match (&input, &inputs, window_elapsed) {
            (Some(input), Some(inputs), Some(end)) if selected && projectable => {
                checkpoints::fences(input, inputs, read_outputs, end)?
            }
            _ => Vec::new(),
        };
        let connected_after = input
            .as_ref()
            .and_then(|input| input.actions.first())
            .and_then(|action| i64::try_from(action.offset_ms).ok())
            .and_then(|ms| {
                start
                    .and_then(|start| start.checked_add_signed(chrono::TimeDelta::milliseconds(ms)))
            });
        Ok(Some(Window {
            selected,
            case,
            start,
            connected_after,
            end: closed_at,
            namespaces,
            projectable,
            inputs: inputs
                .map(|inputs| inputs.acknowledgements)
                .unwrap_or_default(),
            fences,
        }))
    }
}

fn tracked_inputs(input: &InputTranscript) -> Option<TrackedInputs> {
    if input.actions.len() > 128 {
        return None;
    }
    let first = input.actions.first()?;
    let packet = |action: &crate::interaction::model::InputAction| {
        let InputActionKind::Message { message } = &action.action else {
            return None;
        };
        if message.kind != crate::interaction::model::MessageKind::Text || action.ack_ref.is_some()
        {
            return None;
        }
        decode_engine_io_text(&message.data, input.policy.max_message_bytes).ok()
    };
    let EngineIoPacket::Message(connect) = packet(first)? else {
        return None;
    };
    if connect.kind != SocketIoKind::Connect {
        return None;
    }
    let mut ack_ids = BTreeMap::new();
    let mut inputs = Vec::new();
    let mut unacknowledged = Vec::new();
    let mut close_ms = None;
    for action in input.actions.iter().skip(1) {
        if matches!(action.action, InputActionKind::TransportEnd { .. }) {
            // InputTranscript::validate confines this independent physical end
            // to the final action. It carries no business completion barrier.
            continue;
        }
        if matches!(action.action, InputActionKind::Close { .. }) {
            close_ms.get_or_insert(action.offset_ms);
            continue;
        }
        let event = match packet(action)? {
            EngineIoPacket::Pong(_) if action.after.is_empty() && !action.compressible_gap => {
                // Both legacy recorded PONG actions and explicit heartbeat
                // programs retain their own transport scheduler. A PONG has no
                // Socket.IO ACK and must not disable unrelated native inputs.
                continue;
            }
            EngineIoPacket::Message(event)
                if event.kind == SocketIoKind::Disconnect
                    && event.namespace == connect.namespace
                    && close_ms.is_none() =>
            {
                close_ms = Some(action.offset_ms);
                continue;
            }
            EngineIoPacket::Message(event) => event,
            _ => return None,
        };
        if close_ms.is_some()
            || event.kind != SocketIoKind::Event
            || event.attachments != 0
            || event.namespace != connect.namespace
            || matches!(
                event
                    .event_name()
                    .and_then(|name| input.policy.completion_for(&event.namespace, name)),
                Some(crate::interaction::policy::CompletionRule::TerminalEvent { .. })
            )
        {
            return None;
        }
        let Some(id) = event.id else {
            unacknowledged.push((action.sequence, action.offset_ms));
            continue;
        };
        if ack_ids
            .insert(id, (action.sequence, action.offset_ms))
            .is_some()
        {
            return None;
        }
        inputs.push(InputClock {
            sequence: action.sequence,
            offset_ms: action.offset_ms,
            offset_us: action.offset_us,
        });
    }
    Some(TrackedInputs {
        acknowledgements: inputs,
        ack_ids,
        unacknowledged,
        close_ms,
    })
}
fn namespaces(input: &InputTranscript) -> BTreeSet<String> {
    input
        .actions
        .iter()
        .filter_map(|action| {
            let InputActionKind::Message { message } = &action.action else {
                return None;
            };
            if message.kind != crate::interaction::model::MessageKind::Text {
                return None;
            }
            let EngineIoPacket::Message(packet) =
                decode_engine_io_text(&message.data, input.policy.max_message_bytes).ok()?
            else {
                return None;
            };
            (packet.kind == SocketIoKind::Connect).then_some(packet.namespace)
        })
        .collect()
}
