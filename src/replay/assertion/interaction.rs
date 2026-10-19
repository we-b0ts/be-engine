//! Assert independently observed semantic messages and complete connection closure.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;

use super::model::{ResponseAssertionCaseReport, ResponseDifference};

pub(super) fn decrypt_output_bytes(
    bytes: &[u8],
    path: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    let mut response: Value = serde_json::from_slice(bytes)?;
    if crate::interaction::private::decrypt_output(&mut response, path)? {
        return Ok(Some(serde_json::to_vec(&response)?));
    }
    Ok(None)
}

pub(super) fn validate_input(
    input: Option<&crate::interaction::model::InputTranscript>,
    expected: Option<&OutputObservation>,
) -> Result<()> {
    match (input, expected) {
        (Some(input), Some(output)) => {
            input.validate()?;
            ensure!(
                input.protocol == output.protocol,
                "Source interaction input/output protocols disagree"
            );
        }
        (None, None) => {}
        _ => anyhow::bail!(
            "Source interaction input/output evidence is incomplete; re-record this case"
        ),
    }
    Ok(())
}
use crate::interaction::model::{
    MessageKind, OutputObservation, Protocol, TRANSCRIPT_VERSION, WireMessage,
};

pub(super) fn compare(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let (expected, actual) = match (expected, actual) {
        (None, None) => return Ok(()),
        (Some(expected), Some(actual)) => (expected, actual),
        _ => {
            mismatch(report, "$interaction");
            return Ok(());
        }
    };
    ensure!(
        expected.version == TRANSCRIPT_VERSION && actual.version == TRANSCRIPT_VERSION,
        "unsupported interaction output observation version; re-record this case"
    );
    if expected.protocol != actual.protocol {
        mismatch(report, "$interaction/protocol");
    }
    // Matching truncated or incomplete captures never proves compatibility.
    if !expected.end.clean || !actual.end.clean {
        mismatch(report, "$interaction/end/clean");
    }
    if expected.end.reason != actual.end.reason {
        mismatch(report, "$interaction/end/reason");
    }
    if expected.end.pending != actual.end.pending {
        mismatch(report, "$interaction/end/pending");
    }
    if expected.end.close != actual.end.close {
        mismatch(report, "$interaction/end/close");
    }
    let expected_events = comparable(expected)?;
    let actual_events = comparable(actual)?;
    if expected_events.len() != actual_events.len() {
        mismatch(report, "$interaction/events/length");
    }
    for (index, (expected, actual)) in expected_events.iter().zip(&actual_events).enumerate() {
        if expected != actual {
            mismatch(report, &format!("$interaction/events/{index}"));
        }
    }
    Ok(())
}

fn comparable(observation: &OutputObservation) -> Result<Vec<WireMessage>> {
    let events = observation.events.iter().filter(|event| !event.heartbeat);
    if observation.protocol == Protocol::RawStream {
        let mut bytes = Vec::new();
        for event in events {
            bytes.extend_from_slice(&event.message.decode()?);
        }
        return Ok(vec![WireMessage::binary(&bytes)]);
    }
    let mut server_ordinals: BTreeMap<String, u64> = BTreeMap::new();
    events
        .map(|event| {
            let message = &event.message;
            if observation.protocol == Protocol::SocketIo && message.kind == MessageKind::Text {
                let mut message = normalize_transport_identity(message)?;
                if message.data.starts_with('4')
                    && let crate::interaction::socketio::EngineIoPacket::Message(mut packet) =
                        crate::interaction::socketio::decode_engine_io_text(
                            &message.data,
                            usize::MAX,
                        )?
                {
                    if matches!(
                        packet.kind,
                        crate::interaction::socketio::SocketIoKind::Event
                            | crate::interaction::socketio::SocketIoKind::BinaryEvent
                    ) {
                        let ordinal = server_ordinals.entry(packet.namespace.clone()).or_default();
                        // A server-generated ACK ID identifies this event's occurrence.
                        if packet.id.is_some() {
                            packet.id = Some(*ordinal);
                        }
                        *ordinal += 1;
                    }
                    message = WireMessage::text(packet.encode_engine_io()?);
                }
                return Ok(message);
            }
            Ok(message.clone())
        })
        .collect()
}

/// Only protocol-owned session IDs vary. Business fields named `sid` stay strict.
fn normalize_transport_identity(message: &WireMessage) -> Result<WireMessage> {
    let data = &message.data;
    let json_offset = if data.starts_with('0') {
        Some(1)
    } else if let Some(remainder) = data.strip_prefix("40") {
        if remainder.starts_with('/') {
            data.find(',').map(|index| index + 1)
        } else {
            Some(2)
        }
    } else {
        None
    };
    let Some(offset) = json_offset.filter(|offset| *offset < data.len()) else {
        return Ok(message.clone());
    };
    let mut value: Value = serde_json::from_str(&data[offset..])?;
    if let Some(object) = value.as_object_mut() {
        object.remove("sid");
    }
    Ok(WireMessage::text(format!(
        "{}{}",
        &data[..offset],
        serde_json::to_string(&value)?
    )))
}

fn mismatch(report: &mut ResponseAssertionCaseReport, pointer: &str) {
    let mut difference = ResponseDifference::body_value_mismatch();
    difference.pointer = pointer.to_owned();
    report.differences.push(difference);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::model::{EndObservation, EndReason, OutputEvent};

    fn output(protocol: Protocol, messages: &[&[u8]]) -> OutputObservation {
        OutputObservation {
            version: TRANSCRIPT_VERSION,
            protocol,
            events: messages
                .iter()
                .enumerate()
                .map(|(index, message)| OutputEvent {
                    sequence: index as u64,
                    offset_ms: index as u64,
                    heartbeat: false,
                    message: WireMessage::binary(message),
                })
                .collect(),
            end: EndObservation {
                reason: EndReason::ServerEof,
                offset_ms: 100,
                pending: Vec::new(),
                clean: true,
                close: None,
            },
        }
    }

    #[test]
    fn raw_stream_comparison_is_independent_of_http_chunk_boundaries() {
        assert_eq!(
            comparable(&output(Protocol::RawStream, &[b"he", b"llo"])).unwrap(),
            comparable(&output(Protocol::RawStream, &[b"hello"])).unwrap()
        );
    }

    #[test]
    fn only_protocol_session_identifiers_are_normalized() {
        assert_eq!(
            normalize_transport_identity(&WireMessage::text("40/chat,{\"sid\":\"source\"}"))
                .unwrap(),
            normalize_transport_identity(&WireMessage::text("40/chat,{\"sid\":\"target\"}"))
                .unwrap()
        );
        assert_ne!(
            normalize_transport_identity(&WireMessage::text("42[\"event\",{\"sid\":\"source\"}]"))
                .unwrap(),
            normalize_transport_identity(&WireMessage::text("42[\"event\",{\"sid\":\"target\"}]"))
                .unwrap()
        );
    }
}
