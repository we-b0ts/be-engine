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
    pub passive: bool,
    pub selected: bool,
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
        let closed_at = elapsed
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
                    )
                )
        });
        // Fast multi-action programs need an additional causal input proof.
        // Initially support passive namespace subscriptions, whose only input
        // is CONNECT; unsupported or overlapping windows keep inputs unused.
        let passive = complete
            && clean
            && start.zip(closed_at).is_some_and(|(start, end)| end > start)
            && input.as_ref().is_some_and(|input| {
                input.actions.len() == 1
                    && namespaces.len() == 1
                    && input.actions[0].ack_ref.is_none()
                    && elapsed.is_some_and(|end| {
                        input.actions[0].offset_ms < end && end <= input.policy.max_duration_ms
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
            passive,
        });
        ensure!(
            windows.len() <= 16_384,
            "native notification window inventory exceeds bound"
        );
    }
    Ok(windows)
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
