//! Socket.IO framing stays exact; each business argument is a global JSON carrier.
use super::*;
use crate::interaction::socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text};

pub(super) fn compare_message(
    source: &WireMessage,
    target: &WireMessage,
    global: &crate::policy::CompiledJsonPolicy,
    times: super::super::RequestTimes,
    pointer: &str,
) -> Result<Option<Comparison>> {
    if source.kind != MessageKind::Text
        || !["42", "43", "45", "46"]
            .iter()
            .any(|prefix| source.data.starts_with(prefix))
    {
        return Ok(None);
    }
    let EngineIoPacket::Message(source) = decode_engine_io_text(&source.data, 1024 * 1024)? else {
        return Ok(None);
    };
    if !matches!(
        source.kind,
        SocketIoKind::Event
            | SocketIoKind::BinaryEvent
            | SocketIoKind::Ack
            | SocketIoKind::BinaryAck
    ) {
        return Ok(None);
    }
    let prefix = format!("{pointer}/data/socketio");
    let mut result = Comparison::default();
    let target = if target.kind == MessageKind::Text {
        decode_engine_io_text(&target.data, 1024 * 1024).ok()
    } else {
        None
    };
    let Some(EngineIoPacket::Message(target)) = target else {
        mismatch(&mut result, &prefix);
        return Ok(Some(result));
    };
    for (field, equal) in [
        ("kind", source.kind == target.kind),
        ("namespace", source.namespace == target.namespace),
        ("id", source.id == target.id),
        ("attachments", source.attachments == target.attachments),
        ("binary", source.binary == target.binary),
    ] {
        if !equal {
            mismatch(&mut result, &format!("{prefix}/{field}"));
        }
    }
    let is_event = matches!(source.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent);
    let binary = source.attachments > 0 || target.attachments > 0;
    let source = source
        .data
        .as_ref()
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("Source Socket.IO business packet requires argument-array data")
        })?;
    let Some(target) = target.data.as_ref().and_then(Value::as_array) else {
        mismatch(&mut result, &format!("{prefix}/arguments"));
        return Ok(Some(result));
    };
    if source.len() != target.len() {
        mismatch(&mut result, &format!("{prefix}/arguments/length"));
    }
    if is_event && source.first() != target.first() {
        mismatch(&mut result, &format!("{prefix}/event"));
    }
    let first = usize::from(is_event);
    for (index, (source, target)) in source
        .iter()
        .skip(first)
        .zip(target.iter().skip(first))
        .enumerate()
    {
        if binary {
            compare_placeholders(
                source,
                target,
                &format!("{prefix}/arguments/{index}"),
                &mut result,
            );
        }
        let mut checked = crate::value_contract::global::compare(
            &serde_json::to_vec(source)?,
            &serde_json::to_vec(target)?,
            global,
            &[],
            crate::value_contract::json::AnchorClocks {
                case: times,
                dependency: times,
                ..Default::default()
            },
        )?;
        checked.scope_schema_clocks(index);
        for difference in &mut checked.differences {
            difference.pointer = format!("{prefix}/arguments/{index}{}", difference.pointer);
        }
        result.merge_and_validate(checked);
    }
    Ok(Some(result))
}

fn compare_placeholders(source: &Value, target: &Value, pointer: &str, result: &mut Comparison) {
    let placeholder = |value: &Value| value.get("_placeholder") == Some(&Value::Bool(true));
    if placeholder(source) || placeholder(target) {
        if source != target {
            mismatch(result, &format!("{pointer}/binary_placeholder"));
        }
        return;
    }
    match (source, target) {
        (Value::Object(source), Value::Object(target)) => {
            for key in source
                .keys()
                .chain(target.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                compare_placeholders(
                    source.get(key).unwrap_or(&Value::Null),
                    target.get(key).unwrap_or(&Value::Null),
                    &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                    result,
                );
            }
        }
        (Value::Array(source), Value::Array(target)) => {
            for index in 0..source.len().max(target.len()) {
                compare_placeholders(
                    source.get(index).unwrap_or(&Value::Null),
                    target.get(index).unwrap_or(&Value::Null),
                    &format!("{pointer}/{index}"),
                    result,
                );
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
