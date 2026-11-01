//! Original input namespaces and lifecycle bounds, never response frames.
use super::*;
use crate::interaction::{
    model::{InputActionKind, InputTranscript, Protocol},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use serde::Deserialize;
use serde_json::Value;
use std::io::BufReader;

pub(super) struct Window {
    pub case: String,
    pub start: Option<DateTime<Utc>>,
    pub connected_after: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub namespaces: BTreeSet<String>,
    pub projectable: bool,
    pub inputs: Vec<(u64, u64)>,
    pub untracked_at_ms: Option<u64>,
    pub selected: bool,
}

struct TrackedInputs {
    acknowledgements: Vec<(u64, u64)>,
    untracked_at_ms: Option<u64>,
}

#[derive(Deserialize)]
struct Request {
    timestamp: Option<DateTime<Utc>>,
    interaction: Option<Value>,
}
#[derive(Deserialize)]
struct Response {
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

pub(super) fn load(root: &Path, selected: &BTreeMap<String, ReplayCase>) -> Result<Vec<Window>> {
    // A standard completed run provides *all* windows, including skipped Cases.
    // Without that boundary we cannot prove unique finite input ownership.
    let complete = root
        .ancestors()
        .any(|p| p.join("recording-run.json").is_file());
    let files = if complete {
        crate::dependency_index::store::recording_files(root)?.1
    } else {
        // Known namespaces still fence old timers, but incomplete run scope
        // cannot grant a unique Case projection.
        selected
            .values()
            .map(|case| case.dependencies_path.clone())
            .collect()
    };
    let mut windows = Vec::new();
    for file in files {
        let directory = file.parent().context("Case has no directory")?;
        let Some(request) = read_input(&directory.join("request.json"))? else {
            continue;
        };
        let Some(interaction) = request.interaction.filter(|v| v["protocol"] == "socket_io") else {
            continue;
        };
        let start = request.timestamp;
        let case = directory
            .file_name()
            .and_then(|v| v.to_str())
            .context("Case has no identity")?
            .to_owned();
        let input = serde_json::from_value::<InputTranscript>(interaction)
            .ok()
            .filter(|input| input.validate().is_ok());
        let namespaces = input.as_ref().map(namespaces).unwrap_or_default();
        let response = if !complete {
            None
        } else {
            match read::<Response>(&directory.join("expected-response.json"))? {
                Some(response) => Some(response),
                None => read::<Response>(&directory.join("expected_response.json"))?,
            }
        };
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
        // Only the prefix preceding an input without an ACK is projectable.
        // Retain later ACK identities for actual transport receipts, without
        // using them to grant notifications beyond that prefix.
        let inputs = input.as_ref().and_then(tracked_inputs);
        let untracked_at_ms = inputs.as_ref().and_then(|inputs| inputs.untracked_at_ms);
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
        let connected_after = input
            .as_ref()
            .and_then(|input| input.actions.first())
            .and_then(|action| i64::try_from(action.offset_ms).ok())
            .and_then(|ms| {
                start
                    .and_then(|start| start.checked_add_signed(chrono::TimeDelta::milliseconds(ms)))
            });
        windows.push(Window {
            selected: selected.contains_key(&case),
            case,
            start,
            connected_after,
            end: closed_at,
            namespaces,
            projectable,
            inputs: inputs
                .map(|inputs| inputs.acknowledgements)
                .unwrap_or_default(),
            untracked_at_ms,
        });
        ensure!(
            windows.len() <= 16_384,
            "native notification window inventory exceeds bound"
        );
    }
    Ok(windows)
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
    let mut ids = BTreeSet::new();
    let mut inputs = Vec::new();
    let mut untracked_at_ms = None;
    for action in input.actions.iter().skip(1) {
        if matches!(action.action, InputActionKind::TransportEnd { .. }) {
            // InputTranscript::validate confines this independent physical end
            // to the final action. It carries no business completion barrier.
            continue;
        }
        if matches!(action.action, InputActionKind::Close { .. }) {
            untracked_at_ms.get_or_insert(action.offset_ms);
            continue;
        }
        let event = match packet(action)? {
            EngineIoPacket::Pong(_) if action.after.is_empty() && !action.compressible_gap => {
                // Both legacy recorded PONG actions and explicit heartbeat
                // programs retain their own transport scheduler. A PONG has no
                // Socket.IO ACK and must not disable unrelated native inputs.
                continue;
            }
            EngineIoPacket::Message(event) => event,
            _ => return None,
        };
        if event.kind != SocketIoKind::Event
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
            untracked_at_ms.get_or_insert(action.offset_ms);
            continue;
        };
        if !ids.insert(id) {
            return None;
        }
        inputs.push((action.sequence, action.offset_ms));
    }
    Some(TrackedInputs {
        acknowledgements: inputs,
        untracked_at_ms,
    })
}

fn read_input(path: &Path) -> Result<Option<Request>> {
    if !path
        .try_exists()
        .context("native notification INPUT unavailable")?
    {
        return Ok(None);
    }
    // Use the same authenticated in-memory view as request execution. Cipher
    // failures must propagate; they cannot downgrade INPUT to an unknown
    // namespace or release the obsolete subscription-age timer.
    let raw = crate::request_headers::load_request_file(path)
        .context("native notification INPUT unavailable")?;
    serde_json::from_slice(&raw)
        .map(Some)
        .context("invalid original native INPUT metadata")
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::File::open(path) {
        Ok(file) => serde_json::from_reader(BufReader::new(file))
            .map(Some)
            .context("invalid original native lifecycle metadata"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("original native lifecycle metadata unavailable"),
    }
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
