use super::*;
use serde_json::json;

#[test]
fn global_sse_strategy_does_not_require_event_or_json_type_selectors() {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /item_id: {kind: identity, formats: [{prefix: msg_, hex: 2}]}
"#,
    )
    .unwrap();
    let frame = |event: &str, id: &str| {
        let raw = format!("event: {event}\ndata: {{\"item_id\":\"{id}\",\"stable\":true}}\n\n");
        let mut decoder = crate::interaction::stream::StreamDecoder::new(
            crate::interaction::model::Protocol::Sse,
            1024,
        )
        .unwrap();
        decoder.feed(raw.as_bytes()).unwrap().pop().unwrap().message
    };
    let source = frame("arbitrary", "msg_01");
    let target = frame("arbitrary", "msg_02");
    assert!(
        compare_message(
            &source,
            &target,
            compiled.global_json.as_ref(),
            Default::default(),
            "$interaction/events/0",
            &Default::default(),
            Default::default()
        )
        .passed()
    );
    let changed = frame("changed-envelope", "msg_02");
    assert!(
        !compare_message(
            &source,
            &changed,
            compiled.global_json.as_ref(),
            Default::default(),
            "$interaction/events/0",
            &Default::default(),
            Default::default()
        )
        .passed()
    );
}

#[test]
fn sse_reused_created_at_uses_elapsed_to_each_frame_in_either_execution() {
    use crate::interaction::model::{EndObservation, EndReason, OutputEvent, TRANSCRIPT_VERSION};
    use crate::value_contract::time::ClockPair;
    let compiled = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\njson:\n  fields:\n    /response/created_at: {kind: time, formats: [unix_seconds]}\n",
    ).unwrap();
    let observation = |created, end_ms| OutputObservation {
        version: TRANSCRIPT_VERSION,
        protocol: Protocol::Sse,
        events: [10, end_ms]
            .into_iter()
            .enumerate()
            .map(|(index, offset_ms)| OutputEvent {
                sequence: index as u64,
                offset_ms,
                heartbeat: false,
                message: WireMessage::text(
                    serde_json::to_string(&SseEvent {
                        event: Some(
                            if index == 0 {
                                "response.created"
                            } else {
                                "response.completed"
                            }
                            .into(),
                        ),
                        id: None,
                        retry: None,
                        data: json!({"response":{"created_at":created},"stable":true}).to_string(),
                    })
                    .unwrap(),
                ),
            })
            .collect(),
        end: EndObservation {
            reason: EndReason::ServerEof,
            offset_ms: end_ms + 1,
            pending: vec![],
            clean: true,
            partial_message: None,
            close: None,
        },
    };
    let requests = ClockPair {
        source: chrono::DateTime::from_timestamp(1000, 0),
        target: chrono::DateTime::from_timestamp(2000, 0),
    };
    let streams = ClockPair {
        source: chrono::DateTime::from_timestamp(1003, 0),
        target: chrono::DateTime::from_timestamp(2003, 0),
    };
    let compare = |source: &OutputObservation, target: &OutputObservation, requests| {
        super::super::compare_outputs_global(
            Some(source),
            Some(target),
            compiled.global_json.as_ref(),
            streams,
            requests,
        )
        .unwrap()
    };
    for (source_ms, target_ms) in [(300000, 2000), (2000, 300000), (300000, 300000)] {
        for offset in [0, 86400, -86400] {
            let source = observation(1001 + offset, source_ms);
            let target = observation(2001 + offset, target_ms);
            let result = compare(&source, &target, requests);
            assert!(result.passed(), "{:?}", result.differences);
        }
    }
    let source = observation(1001, 300000);
    let target = observation(2001, 2000);
    assert!(!compare(&source, &target, Default::default()).passed());
    let early_error = compare(&source, &observation(2010, 2000), requests);
    assert!(
        early_error
            .differences
            .iter()
            .any(|diff| diff.pointer == "$interaction/events/0/sse/data/response/created_at"),
        "a later frame's elapsed budget cannot authorize an early timestamp"
    );
}

#[test]
fn primary_sse_reuses_delivered_times_without_rebasing_local_times_or_future_reads() {
    use crate::interaction::model::{EndObservation, EndReason, OutputEvent, TRANSCRIPT_VERSION};
    use crate::value_contract::{
        time::ClockPair,
        time_copies::{TimeCopyPosition, TimeCopyRecord, TimeCopyStore},
    };
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /block/timestamp: {kind: time, formats: [unix_milliseconds]}
    /response/blocks/*/timestamp: {kind: time, formats: [unix_milliseconds]}
    /response/created_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap();
    let plan = compiled.global_json.as_ref().unwrap();
    let time = plan.fields["/block/timestamp"]
        .select_contract_with_clock(&json!(1010000), chrono::DateTime::from_timestamp(1000, 0))
        .unwrap()
        .time()
        .unwrap();
    let position = TimeCopyPosition::Http {
        host: "stream.test",
        port: 80,
        exchange: "original",
    };
    let mut store = TimeCopyStore::default();
    store.set_record_clocks(ClockPair {
        source: chrono::DateTime::from_timestamp(1100, 0),
        target: chrono::DateTime::from_timestamp(2300, 0),
    });
    store
        .record_batch(
            "case",
            vec![
                TimeCopyRecord::new_time(
                    &time,
                    position,
                    position,
                    "/result/blocks/0/timestamp",
                    "/result/blocks/0/timestamp",
                    &json!(1010000),
                    &json!(2210000),
                )
                .unwrap(),
            ],
        )
        .unwrap();
    let copies = store.delivered_copies("case");
    let observation = |created, stamp, block_offset| {
        OutputObservation {
        version: TRANSCRIPT_VERSION,
        protocol: Protocol::Sse,
        events: [
            (10, json!({"response":{"created_at":created}})),
            (
                block_offset,
                json!({"block":{"timestamp":stamp},"stable":7}),
            ),
            (
                block_offset + 1,
                json!({"response":{"created_at":created + block_offset / 1000,"blocks":[{"timestamp":stamp}]}}),
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (offset, data))| OutputEvent {
            sequence: index as u64,
            offset_ms: offset,
            heartbeat: false,
            message: WireMessage::text(
                serde_json::to_string(&SseEvent {
                    event: None,
                    id: None,
                    retry: None,
                    data: data.to_string(),
                })
                .unwrap(),
            ),
        })
        .collect(),
        end: EndObservation {
            reason: EndReason::ServerEof,
            offset_ms: block_offset + 2,
            pending: vec![],
            clean: true,
            partial_message: None,
            close: None,
        },
    }
    };
    let source = observation(1001, 1010000, 100001);
    let target = observation(2001, 2210000, 400001);
    let clocks = ClockPair {
        source: chrono::DateTime::from_timestamp(1000, 0),
        target: chrono::DateTime::from_timestamp(2000, 0),
    };
    let compare =
        |source: &OutputObservation,
         target: &OutputObservation,
         copies: &crate::value_contract::time_copies::DeliveredTimeCopies| {
            super::super::compare_outputs_global_with_time_copies(
                Some(source),
                Some(target),
                Some(plan),
                clocks,
                Default::default(),
                copies,
                None,
                false,
            )
            .unwrap()
            .passed()
        };
    assert!(!compare(&source, &target, &Default::default()));
    assert!(compare(&source, &target, &copies));
    assert!(!compare(
        &source,
        &observation(2001, 2210001, 400001),
        &copies
    ));
    assert!(!compare(
        &source,
        &observation(2210, 2210000, 400001),
        &copies
    ));
    assert!(!compare(
        &observation(1001, 1010000, 99999),
        &target,
        &copies
    ));
    assert!(!compare(
        &source,
        &observation(2001, 2210000, 290000),
        &copies
    ));
}
