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
    let observation = |created, stamp, block_offset| OutputObservation {
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
                json!({"response":{"created_at":created,"blocks":[{"timestamp":stamp}]}}),
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
    };
    let source = observation(1001, 1010000, 100001);
    let target = observation(2001, 2210000, 300001);
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
                copies,
                None,
            )
            .unwrap()
            .passed()
        };
    assert!(!compare(&source, &target, &Default::default()));
    assert!(compare(&source, &target, &copies));
    assert!(!compare(
        &source,
        &observation(2001, 2210001, 300001),
        &copies
    ));
    assert!(!compare(
        &source,
        &observation(2210, 2210000, 300001),
        &copies
    ));
    assert!(!compare(
        &observation(1001, 1010000, 99999),
        &target,
        &copies
    ));
    assert!(!compare(
        &source,
        &observation(2001, 2210000, 299999),
        &copies
    ));
}
