//! Verify native stream framing and independently observed interaction messages.
//! Business values are delegated to the caller's registered value services.
use super::model::{
    EndReason, MessageKind, OutputObservation, Protocol, TRANSCRIPT_VERSION, WireMessage,
};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_contract::{
    compare::{AnchorClocks, Comparison, Difference},
    time::ClockPair,
};

mod client_ack;
pub use client_ack::Context as AckContext;
pub mod socketio;
pub mod sse;

/// The host supplies value semantics and authenticated delivered-value provenance.
pub trait ValueComparator {
    fn compare(&self, source: &[u8], target: &[u8], clocks: AnchorClocks) -> Result<Comparison>;

    fn compare_sse_data(
        &self,
        source: &[u8],
        target: &[u8],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        self.compare(source, target, clocks)
    }
}

#[derive(Clone, Copy)]
pub struct ComparisonContext<'a> {
    pub times: ClockPair,
    pub request_times: ClockPair,
    pub ack_context: Option<&'a AckContext>,
    pub source_heartbeat_tail: bool,
    pub max_message_bytes: usize,
}

pub fn validate_input(
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
pub fn compare_outputs(
    expected: Option<&OutputObservation>,
    actual: Option<&OutputObservation>,
    values: Option<&dyn ValueComparator>,
    context: &ComparisonContext<'_>,
) -> Result<Comparison> {
    let ComparisonContext {
        times,
        request_times,
        ack_context,
        source_heartbeat_tail,
        max_message_bytes,
    } = *context;
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
    let heartbeat_grace = actual.protocol == Protocol::SocketIo
        && source_heartbeat_tail
        && actual
            .end
            .fast_heartbeat_eof_ms
            .is_some_and(|at| at <= actual.end.offset_ms)
        && matches!(
            actual.end.reason,
            EndReason::ServerEof | EndReason::FastHeartbeatTailSkipped
        );
    let heartbeat_tail_skipped = actual.protocol == Protocol::SocketIo
        && actual.end.reason == EndReason::FastHeartbeatTailSkipped
        && actual.end.close.is_none()
        && source_heartbeat_tail;
    if expected.end.reason != actual.end.reason && !heartbeat_tail_skipped {
        mismatch(&mut report, "$interaction/end/reason");
    }
    if expected.end.pending != actual.end.pending {
        mismatch(&mut report, "$interaction/end/pending");
    }
    if expected.end.close != actual.end.close && !(heartbeat_tail_skipped || heartbeat_grace) {
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
    let allowed_suffix = heartbeat_grace
        && actual_events
            .get(expected_events.len()..)
            .is_some_and(|suffix| socketio::business_event_suffix(suffix, max_message_bytes));
    let aligned_events = if allowed_suffix {
        &actual_events[..expected_events.len()]
    } else {
        &actual_events
    };
    let alignment = ack_context
        .filter(|_| socketio)
        .map(|context| context.alignment(&expected_events, aligned_events, &source_offsets))
        .unwrap_or_else(|| (0..aligned_events.len()).collect());
    let target_offsets = actual
        .events
        .iter()
        .filter(|event| !event.heartbeat)
        .map(|event| event.offset_ms)
        .collect::<Vec<_>>();
    if expected_events.len() != actual_events.len() && !allowed_suffix {
        mismatch(&mut report, "$interaction/events/length");
    }
    for (index, expected) in expected_events.iter().take(actual_events.len()).enumerate() {
        let actual_index = alignment[index];
        let actual = &actual_events[actual_index];
        let pointer = format!("$interaction/events/{index}");
        let observed = ClockPair {
            source: source_offsets
                .get(index)
                .and_then(|offset| event_clock(times.source, *offset)),
            target: target_offsets
                .get(actual_index)
                .and_then(|offset| event_clock(times.target, *offset)),
        };
        let clocks = AnchorClocks::for_response(request_times, observed);
        if sse && values.is_some() {
            let first_difference = report.differences.len();
            let mut comparison = sse::compare_message(expected, actual, values, clocks, &pointer);
            comparison.scope_schema_clocks(index);
            report.merge_and_validate(comparison);
            for diff in &mut report.differences[first_difference..] {
                if diff.pointer.is_empty() {
                    diff.pointer = pointer.clone();
                }
            }
        } else if let Some(values) = values {
            if expected.kind != actual.kind {
                mismatch(&mut report, &pointer);
            }
            let adapted = if socketio {
                socketio::compare_message(
                    expected,
                    actual,
                    values,
                    clocks,
                    &pointer,
                    max_message_bytes,
                )?
            } else {
                None
            };
            let mut comparison = if let Some(comparison) = adapted {
                comparison
            } else {
                let mut comparison =
                    values.compare(&expected.decode()?, &actual.decode()?, clocks)?;
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
                missing_predecessor: None,
                dispatch_timeout: None,
                fast_heartbeat_eof_ms: None,
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
    fn heartbeat_eof_accepts_only_an_extra_business_suffix_after_an_exact_prefix() {
        let event = |message| OutputEvent {
            sequence: 1,
            offset_ms: 1,
            heartbeat: false,
            message: WireMessage::text(message),
        };
        let mut expected = output(Protocol::SocketIo, &[]);
        expected.events.push(event(r#"42["source",1]"#));
        let mut target = expected.clone();
        target.events.push(event(r#"42["extra",2]"#));
        let compare = |actual: &OutputObservation, proven| {
            compare_outputs(
                Some(&expected),
                Some(actual),
                None,
                &ComparisonContext {
                    times: Default::default(),
                    request_times: Default::default(),
                    ack_context: None,
                    source_heartbeat_tail: proven,
                    max_message_bytes: 1024,
                },
            )
            .unwrap()
            .passed()
        };
        assert!(!compare(&target, true));
        target.end.fast_heartbeat_eof_ms = Some(10);
        assert!(!compare(&target, false));
        assert!(compare(&target, true));
        target.end.reason = EndReason::FastHeartbeatTailSkipped;
        assert!(compare(&target, true));
        target.events.swap(0, 1);
        assert!(!compare(&target, true));
        target.events.swap(0, 1);
        target.events[1] = event(r#"431[true]"#);
        assert!(!compare(&target, true));
        target.events.clear();
        assert!(!compare(&target, true));
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

    #[test]
    fn native_values_delegate_with_independent_case_and_event_clocks() {
        #[derive(Default)]
        struct Values(std::cell::RefCell<Vec<(&'static str, AnchorClocks)>>);

        impl ValueComparator for Values {
            fn compare(
                &self,
                source: &[u8],
                target: &[u8],
                clocks: AnchorClocks,
            ) -> Result<Comparison> {
                assert_ne!(source, target);
                self.0.borrow_mut().push(("argument", clocks));
                Ok(Comparison::default())
            }

            fn compare_sse_data(
                &self,
                source: &[u8],
                target: &[u8],
                clocks: AnchorClocks,
            ) -> Result<Comparison> {
                assert_eq!(source, b"source");
                assert_eq!(target, b"target");
                self.0.borrow_mut().push(("sse", clocks));
                Ok(Comparison::default())
            }
        }

        let values = Values::default();
        let context = ComparisonContext {
            times: ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            request_times: ClockPair {
                source: chrono::DateTime::from_timestamp(900, 0),
                target: chrono::DateTime::from_timestamp(1900, 0),
            },
            ack_context: None,
            source_heartbeat_tail: false,
            max_message_bytes: 4096,
        };
        for (protocol, source, target) in [
            (
                Protocol::SocketIo,
                r#"42/chat,9["event","source"]"#,
                r#"42/chat,77["event","target"]"#,
            ),
            (
                Protocol::Sse,
                r#"{"event":"event","id":null,"retry":null,"data":"source"}"#,
                r#"{"event":"event","id":null,"retry":null,"data":"target"}"#,
            ),
        ] {
            let mut source_output = output(protocol, &[]);
            source_output.events.push(OutputEvent {
                sequence: 1,
                offset_ms: 250,
                heartbeat: false,
                message: WireMessage::text(source),
            });
            source_output.end.offset_ms = 1000;
            let mut target_output = source_output.clone();
            target_output.events[0].offset_ms = 700;
            target_output.events[0].message = WireMessage::text(target);
            assert!(
                compare_outputs(
                    Some(&source_output),
                    Some(&target_output),
                    Some(&values),
                    &context,
                )
                .unwrap()
                .passed()
            );
            assert!(
                !compare_outputs(Some(&source_output), Some(&target_output), None, &context)
                    .unwrap()
                    .passed()
            );
        }
        let calls = values.0.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "argument");
        assert_eq!(calls[1].0, "sse");
        for (_, clocks) in calls.iter() {
            assert_eq!(clocks.case.source, context.request_times.source);
            assert_eq!(clocks.case.target, context.request_times.target);
            assert_eq!(
                clocks.observation().source,
                chrono::DateTime::from_timestamp(1000, 250_000_000),
            );
            assert_eq!(
                clocks.observation().target,
                chrono::DateTime::from_timestamp(2000, 700_000_000),
            );
        }
    }
}
