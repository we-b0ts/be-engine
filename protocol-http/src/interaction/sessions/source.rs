//! Native Socket.IO Source identities and clean connection windows.
use super::valid_identity;
use crate::interaction::{
    model::{EndReason, InputActionKind, InputTranscript, MessageKind, Protocol},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ops::Range;

pub fn window(
    request: &Value,
    input: &InputTranscript,
    output: &Value,
) -> Option<Range<DateTime<Utc>>> {
    let start = serde_json::from_value::<DateTime<Utc>>(request["timestamp"].clone()).ok()?;
    let end = &output["interaction"]["end"];
    let reason = serde_json::from_value::<EndReason>(end["reason"].clone()).ok()?;
    if end["clean"] != true
        || !matches!(
            reason,
            EndReason::BusinessIdle
                | EndReason::ClientClose
                | EndReason::ServerEof
                | EndReason::ClientTransportEnd
        )
    {
        return None;
    }
    let elapsed = end["offset_ms"].as_u64()?;
    let transport_end = input
        .actions
        .last()
        .filter(|action| matches!(action.action, InputActionKind::TransportEnd { .. }))
        .map(|action| action.offset_ms);
    if (reason == EndReason::ClientTransportEnd) != transport_end.is_some() {
        return None;
    }
    let elapsed = transport_end.map_or(elapsed, |at| at.min(elapsed));
    if elapsed == 0 || elapsed > input.policy.max_duration_ms {
        return None;
    }
    let elapsed = TimeDelta::try_milliseconds(i64::try_from(elapsed).ok()?)?;
    Some(start..start.checked_add_signed(elapsed)?)
}

pub fn sessions(input: &InputTranscript, output: &Value) -> BTreeMap<String, String> {
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
