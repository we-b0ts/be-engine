//! Assert independently observed semantic messages and complete connection closure.
use crate::value_contract::json::{Comparison, Difference};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;
mod contracts;
mod socketio;
pub(crate) use contracts::decode_sse;

use super::model::ResponseAssertionCaseReport;

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
            if let Some(partial) = partial_message(output)? {
                ensure!(
                    input.actions.iter().any(|action| matches!(
                        action.action,
                        crate::interaction::model::InputActionKind::Close { .. }
                    )) && partial.len() <= input.policy.max_message_bytes,
                    "partial Source stream requires a bounded recorded client close input"
                );
            }
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
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::RequestTimes,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let checked = compare_outputs_global_with_time_copies(expected, actual, global, times, copies)?;
    report.identity_pairs.extend(checked.identity_pairs());
    report.applied_body_rule_ids.extend(checked.evaluated);
    report.differences.extend(
        checked
            .differences
            .into_iter()
            .map(super::unified::contract_difference),
    );
    Ok(())
}

/// One adapter serves Source preflight, independent Target proof and Replay.
pub(crate) fn compare_outputs_global(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::RequestTimes,
) -> Result<Comparison> {
    compare_outputs_global_with_time_copies(expected, actual, global, times, &Default::default())
}

fn compare_outputs_global_with_time_copies(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    global: Option<&crate::policy::CompiledJsonPolicy>,
    times: super::RequestTimes,
    copies: &crate::value_contract::time_copies::DeliveredTimeCopies,
) -> Result<Comparison> {
    let mut report = Comparison::default();
    let (expected, actual) = match (expected, actual) {
        (None, None) => return Ok(report),
        (Some(expected), Some(actual)) => (expected, actual),
        _ => {
            mismatch(&mut report, "$interaction");
            return Ok(report);
        }
    };
    ensure!(
        expected.version == TRANSCRIPT_VERSION && actual.version == TRANSCRIPT_VERSION,
        "unsupported interaction output observation version; re-record this case"
    );
    if expected.protocol != actual.protocol {
        mismatch(&mut report, "$interaction/protocol");
    }
    // Matching truncated or incomplete captures never proves compatibility.
    if !expected.end.clean || !actual.end.clean {
        mismatch(&mut report, "$interaction/end/clean");
    }
    if expected.end.reason != actual.end.reason {
        mismatch(&mut report, "$interaction/end/reason");
    }
    if expected.end.pending != actual.end.pending {
        mismatch(&mut report, "$interaction/end/pending");
    }
    if expected.end.close != actual.end.close {
        mismatch(&mut report, "$interaction/end/close");
    }
    if partial_message(expected)? != partial_message(actual)? {
        mismatch(&mut report, "$interaction/end/partial_message");
    }
    let expected_events = comparable(expected)?;
    let actual_events = comparable(actual)?;
    let sse = expected.protocol == Protocol::Sse && actual.protocol == Protocol::Sse;
    let socketio = expected.protocol == Protocol::SocketIo && actual.protocol == Protocol::SocketIo;
    let source_offsets = expected
        .events
        .iter()
        .filter(|event| !event.heartbeat)
        .map(|event| event.offset_ms)
        .collect::<Vec<_>>();
    let target_offsets = actual
        .events
        .iter()
        .filter(|event| !event.heartbeat)
        .map(|event| event.offset_ms)
        .collect::<Vec<_>>();
    if expected_events.len() != actual_events.len() {
        mismatch(&mut report, "$interaction/events/length");
    }
    for (index, (expected, actual)) in expected_events.iter().zip(&actual_events).enumerate() {
        let pointer = format!("$interaction/events/{index}");
        if sse && global.is_some() {
            let first_difference = report.differences.len();
            let observed = super::RequestTimes {
                source: event_clock(times.source, source_offsets[index]),
                target: event_clock(times.target, target_offsets[index]),
            };
            let mut comparison = contracts::compare_message(
                expected, actual, global, times, &pointer, copies, observed,
            );
            comparison.scope_schema_clocks(index);
            report.merge_and_validate(comparison);
            for diff in &mut report.differences[first_difference..] {
                if diff.pointer.is_empty() {
                    diff.pointer = pointer.clone();
                }
            }
        } else if let Some(global) = global {
            if expected.kind != actual.kind {
                mismatch(&mut report, &pointer);
            }
            let adapted = if socketio {
                socketio::compare_message(expected, actual, global, times, &pointer)?
            } else {
                None
            };
            let mut comparison = if let Some(comparison) = adapted {
                comparison
            } else {
                let mut comparison = crate::value_contract::global::compare(
                    &expected.decode()?,
                    &actual.decode()?,
                    global,
                    &[],
                    crate::value_contract::json::AnchorClocks {
                        case: times,
                        dependency: times,
                        ..Default::default()
                    },
                )?;
                for difference in &mut comparison.differences {
                    difference.pointer = format!("{pointer}/data{}", difference.pointer);
                }
                comparison
            };
            comparison.scope_schema_clocks(index);
            report.merge_and_validate(comparison);
        } else if expected != actual {
            mismatch(&mut report, &pointer);
        }
    }
    Ok(report)
}

fn event_clock(
    started: Option<chrono::DateTime<chrono::Utc>>,
    offset: u64,
) -> Option<chrono::DateTime<chrono::Utc>> {
    started?.checked_add_signed(chrono::TimeDelta::try_milliseconds(
        i64::try_from(offset).ok()?,
    )?)
}

fn partial_message(observation: &OutputObservation) -> Result<Option<Vec<u8>>> {
    let Some(message) = &observation.end.partial_message else {
        return Ok(None);
    };
    ensure!(
        matches!(
            observation.end.reason,
            crate::interaction::model::EndReason::ClientClose
                | crate::interaction::model::EndReason::DependencyFailure
        ) && matches!(observation.protocol, Protocol::Sse | Protocol::Ndjson)
            && message.kind == MessageKind::Binary,
        "partial stream message requires binary evidence of a framed HTTP close or failed dependency"
    );
    let bytes = message.decode()?;
    ensure!(!bytes.is_empty(), "partial stream message cannot be empty");
    Ok(Some(bytes))
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

fn mismatch(report: &mut Comparison, pointer: &str) {
    report.differences.push(Difference {
        pointer: pointer.into(),
        reason: "interaction value changed".into(),
    });
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
                partial_message: None,
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

    #[test]
    fn partial_stream_prefix_is_exact_and_never_a_successful_eof() {
        let mut expected = output(Protocol::Sse, &[]);
        expected.end.reason = EndReason::ClientClose;
        expected.end.partial_message = Some(WireMessage::binary(b"data: prefix"));
        let mut actual = expected.clone();
        assert_eq!(
            partial_message(&expected).unwrap(),
            partial_message(&actual).unwrap()
        );
        actual.end.partial_message = Some(WireMessage::binary(b"data: different"));
        assert_ne!(
            partial_message(&expected).unwrap(),
            partial_message(&actual).unwrap()
        );
        actual.end.reason = EndReason::ServerEof;
        assert!(partial_message(&actual).is_err());
    }
}
