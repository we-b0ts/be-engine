use super::*;
use serde_json::{Value, json};

fn fixture() -> (KafkaReplayState, KafkaRecord) {
    let capture = |value| json!({"encoding":"utf8","data":value,"truncated":false});
    let connection = Uuid::new_v4();
    let produce: RecordedKafkaProduce = serde_json::from_value(json!({"connection_id":connection,"request_sequence":1,
        "target_host":"kafka.test","target_port":9092,"topic":"items","key":capture("key"),"value":capture("value"),
        "headers":[],"result":"accepted","outcome":"response","duration_ms":0,"replay_safe":true})).unwrap();
    let actual = decode_record(
        produce.topic.clone(),
        produce.key.clone(),
        produce.headers.clone(),
        produce.value.clone(),
        0,
    )
    .unwrap();
    let mut state = KafkaReplayState::default();
    let mut targets = BTreeMap::new();
    state
        .register_produce(produce, ReplaySource::Global, None, &mut targets)
        .unwrap();
    state.register_fetch(serde_json::from_value(json!({"connection_id":connection,"sequence":2,
        "target_host":"kafka.test","target_port":9092,"topics":["items"],"outcome":"response","duration_ms":0,"replay_safe":true})).unwrap(), ReplaySource::Global, None, &mut targets).unwrap();
    state.register_delivery(serde_json::from_value(json!({"connection_id":connection,"fetch_sequence":2,
        "target_host":"kafka.test","target_port":9092,"topic":"items","key":capture("key"),"value":capture("delivered"),
        "headers":[],"message_timestamp_ms":123,"replay_safe":true})).unwrap(), ReplaySource::Global, None, &mut targets).unwrap();
    state.freeze_global_report_layout();
    state.initialize_global_report_usage(3);
    (state, actual)
}

fn equivalent(state: &KafkaReplayState, report: &std::path::Path, rows: &[Row]) {
    let mut extras = Vec::new();
    state
        .visit_global_report_extras(&mut |row| {
            extras.push(row);
            Ok(())
        })
        .unwrap();
    let (count, actual) = crate::replay::report::global_evidence::regular::tests::protocol_snapshot(
        report,
        "kafka",
        state.global_report_usage().layout().to_vec(),
        rows,
        state.global_report_usage().snapshot().unwrap(),
        extras,
    );
    let mut expected: Vec<Value> = Vec::new();
    state
        .visit_global_unused(&mut |row| {
            expected.push(row);
            Ok(())
        })
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(count, state.global_unused_count());
}

#[test]
fn cached_global_reports_follow_real_kafka_commit_and_failure_across_three_sections() {
    for fail in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let report = temp.path().join("report.json");
        let (mut state, actual) = fixture();
        let target = TargetKey {
            host: "kafka.test".into(),
            port: 9092,
        };
        let mut rows = Vec::new();
        state
            .visit_global_report_rows(&mut |row| {
                rows.push(row);
                Ok(())
            })
            .unwrap();
        equivalent(&state, &report, &rows);
        let produce = state
            .reserve_produce(None, &target, &[actual], false)
            .unwrap();
        if fail {
            state.fail_produce(produce, &target, "fixture failed".into());
        } else {
            state.commit_produce(produce);
        }
        equivalent(&state, &report, &rows);
        assert_eq!(state.global_unused_count(), if fail { 3 } else { 2 });
        let fetch = state
            .reserve_fetch(None, &target, &BTreeSet::from(["items".into()]))
            .unwrap();
        equivalent(&state, &report, &rows);
        if fail {
            state.fail_fetch(fetch, &target, "fixture failed".into());
        } else {
            state.commit_fetch(fetch);
        }
        equivalent(&state, &report, &rows);
        assert_eq!(state.global_unused_count(), if fail { 3 } else { 0 });
    }
}
