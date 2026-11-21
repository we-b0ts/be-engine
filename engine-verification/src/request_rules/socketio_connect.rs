//! Exact CONNECT auth positions reuse verified JWT rules; business frames stay opaque.
use super::SocketIoConnectLocation;
use crate::interaction::{
    model::{InputActionKind, InputTranscript, MessageKind},
    socketio::{EngineIoPacket, SocketIoKind, SocketIoPacket, decode_engine_io_text},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;

fn selected(
    request: &Value,
    location: &SocketIoConnectLocation,
) -> Result<Vec<(usize, SocketIoPacket)>> {
    let Some(value) = request
        .get("interaction")
        .filter(|v| v["protocol"] == "socket_io")
    else {
        return Ok(vec![]);
    };
    let input: InputTranscript = serde_json::from_value(value.clone())
        .context("invalid Socket.IO input for JWT selection")?;
    input.validate()?;
    input
        .actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            let InputActionKind::Message { message } = &action.action else {
                return None;
            };
            if message.kind != MessageKind::Text {
                return None;
            }
            match decode_engine_io_text(&message.data, input.policy.max_message_bytes) {
                Ok(EngineIoPacket::Message(packet))
                    if packet.kind == SocketIoKind::Connect
                        && packet.namespace == location.namespace
                        && packet
                            .data
                            .as_ref()
                            .and_then(|data| data.pointer(&location.pointer))
                            .is_some() =>
                {
                    Some(Ok((index, packet)))
                }
                Err(error) => Some(Err(error)),
                _ => None,
            }
        })
        .collect()
}

pub(super) fn token(request: &Value, location: &SocketIoConnectLocation) -> Result<Option<String>> {
    let mut found = None;
    for (_, packet) in selected(request, location)? {
        let Some(value) = packet
            .data
            .as_ref()
            .and_then(|v| v.pointer(&location.pointer))
            .and_then(Value::as_str)
        else {
            continue;
        };
        ensure!(
            found.as_deref().is_none_or(|previous| previous == value),
            "ambiguous JWT values in repeated Socket.IO CONNECT inputs"
        );
        found = Some(value.to_owned());
    }
    Ok(found)
}

pub(super) fn replace(
    request: &mut Value,
    location: &SocketIoConnectLocation,
    token: String,
) -> Result<()> {
    let selected = selected(request, location)?;
    ensure!(
        !selected.is_empty(),
        "Socket.IO CONNECT JWT disappeared during transformation"
    );
    for (index, mut packet) in selected {
        let value = packet
            .data
            .as_mut()
            .and_then(|data| data.pointer_mut(&location.pointer))
            .context("Socket.IO CONNECT JWT field disappeared")?;
        ensure!(
            value.is_string(),
            "Socket.IO CONNECT JWT field changed type"
        );
        *value = Value::String(token.clone());
        request["interaction"]["actions"][index]["action"]["message"]["data"] =
            Value::String(packet.encode_engine_io()?);
    }
    Ok(())
}
