//! Read original namespace CONNECT metadata; retain no expected business payloads.
use super::valid_identity;
use crate::interaction::{
    model::{InputActionKind, InputTranscript, MessageKind, Protocol},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use crate::replay::ReplayCase;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
pub(super) fn load(
    cases: &BTreeMap<String, ReplayCase>,
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let mut result = BTreeMap::new();
    for (case, replay) in cases {
        let request_path = replay.dir.join("request.json");
        if !request_path.is_file() {
            continue;
        }
        let request: Value = serde_json::from_slice(
            &crate::request_headers::load_request_file(&request_path)
                .context("native namespace session INPUT could not be authenticated")?,
        )
        .context("invalid native namespace session INPUT")?;
        if request
            .pointer("/interaction/protocol")
            .and_then(Value::as_str)
            != Some("socket_io")
        {
            continue;
        }
        let Some(input) = serde_json::from_value::<InputTranscript>(request["interaction"].clone())
            .ok()
            .filter(|input| input.validate().is_ok())
        else {
            continue;
        };
        let path = ["expected-response.json", "expected_response.json"]
            .into_iter()
            .map(|name| replay.dir.join(name))
            .find(|path| path.is_file());
        let Some(path) = path else { continue };
        let mut output: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        crate::interaction::private::decrypt_output(&mut output, &path)
            .context("native namespace session Source output could not be authenticated")?;
        let namespaces = sessions(&input, &output);
        if !namespaces.is_empty() {
            result.insert(case.clone(), namespaces);
        }
    }
    Ok(result)
}

pub(super) fn sessions(input: &InputTranscript, output: &Value) -> BTreeMap<String, String> {
    if input.protocol != Protocol::SocketIo
        || output
            .pointer("/interaction/protocol")
            .and_then(Value::as_str)
            != Some("socket_io")
        || output
            .pointer("/interaction/version")
            .and_then(Value::as_u64)
            != Some(u64::from(crate::interaction::model::TRANSCRIPT_VERSION))
    {
        return BTreeMap::new();
    }
    let mut inputs = BTreeMap::<String, usize>::new();
    for action in &input.actions {
        let InputActionKind::Message { message } = &action.action else {
            continue;
        };
        if message.kind != MessageKind::Text || !message.data.starts_with("40") {
            continue;
        }
        if let Ok(EngineIoPacket::Message(packet)) =
            decode_engine_io_text(&message.data, input.policy.max_message_bytes)
            && packet.kind == SocketIoKind::Connect
        {
            *inputs.entry(packet.namespace).or_default() += 1;
        }
    }
    let mut source = BTreeMap::<String, (usize, Option<String>)>::new();
    if let Some(events) = output
        .pointer("/interaction/events")
        .and_then(Value::as_array)
    {
        for event in events {
            if event.pointer("/message/kind").and_then(Value::as_str) != Some("text") {
                continue;
            }
            let Some(data) = event.pointer("/message/data").and_then(Value::as_str) else {
                continue;
            };
            if !data.starts_with("40") {
                continue;
            }
            let Ok(EngineIoPacket::Message(packet)) =
                decode_engine_io_text(data, input.policy.max_message_bytes)
            else {
                continue;
            };
            if packet.kind != SocketIoKind::Connect || inputs.get(&packet.namespace) != Some(&1) {
                continue;
            }
            let entry = source.entry(packet.namespace).or_default();
            entry.0 += 1;
            entry.1 = packet
                .data
                .as_ref()
                .and_then(|data| data.get("sid"))
                .and_then(Value::as_str)
                .filter(|sid| valid_identity(sid))
                .map(str::to_owned);
        }
    }
    source
        .into_iter()
        .filter_map(|(namespace, (count, sid))| {
            (count == 1)
                .then_some(sid)
                .flatten()
                .map(|sid| (namespace, sid))
        })
        .collect()
}
