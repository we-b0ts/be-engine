use crate::protocols::replay::redis::*;
use serde_json::json;

fn fixture(count: usize) -> RedisReplayState {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    for sequence in 0..count {
        let record = serde_json::from_value(json!({
            "connection_id":Uuid::nil(),"sequence":sequence,
            "target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
            "command":"GET","args":[{"encoding":"utf8","data":format!("key:{sequence}")}],
            "response_kind":"bulk_string","response":{"encoding":"utf8","data":"$-1\r\n"},
            "duration_ms":0,"outcome":"response","replay_safe":true
        }))
        .unwrap();
        state
            .register_exchange(record, ReplaySource::Case, Some("case"), &mut targets, &[])
            .unwrap();
    }
    state
}

fn request(
    state: &mut RedisReplayState,
    key: &[u8],
) -> std::result::Result<
    MatchedRedisExchange,
    crate::protocols::replay::redis::report::CommandMatchDiagnostic,
> {
    state.match_redis(
        Some("case"),
        &TargetKey {
            host: "redis.test".into(),
            port: 6379,
        },
        TargetConnection::default(),
        2,
        0,
        None,
        "GET",
        &[key.to_vec()],
    )
}

#[test]
fn success_and_failure_share_admission_order_even_when_deliveries_complete_in_reverse() {
    let mut state = fixture(2);
    let first = request(&mut state, b"key:0").unwrap();
    assert!(request(&mut state, b"unrecorded").is_err());
    assert_eq!(state.events.request_order.latest(Some("case")), Some(1));
    let second = request(&mut state, b"key:1").unwrap();
    state.complete_exchange(&second);
    state.complete_exchange(&first);
    let report = state.snapshot();
    assert_eq!(
        report.target_event_index_scope,
        Some("case_request_admission")
    );
    assert_eq!(report.matched[0].target_event_index, Some(2));
    assert_eq!(report.matched[1].target_event_index, Some(0));
    assert_eq!(report.matched_count, 2);
    assert!(report.unused_case.is_empty());
    assert_eq!(state.events.request_order.reserve(Some("other")), 0);
    assert_eq!(state.events.request_order.reserve(None), 0);
    assert_eq!(state.events.request_order.latest(Some("case")), Some(2));
}

#[test]
fn admission_order_keeps_advancing_after_success_details_are_truncated() {
    let mut state = fixture(103);
    for index in 0..102 {
        let matched = request(&mut state, format!("key:{index}").as_bytes()).unwrap();
        state.complete_exchange(&matched);
    }
    assert!(request(&mut state, b"unrecorded").is_err());
    assert_eq!(state.events.request_order.latest(Some("case")), Some(102));
    let matched = request(&mut state, b"key:102").unwrap();
    assert_eq!(matched.report.target_event_index, Some(103));
    state.complete_exchange(&matched);
    let report = state.snapshot();
    assert_eq!(report.matched_count, 103);
    assert_eq!(report.matched.len(), 100);
    assert_eq!(report.matched[99].target_event_index, Some(99));
    assert!(report.unused_case.is_empty());
}

#[test]
fn failed_response_delivery_keeps_its_original_request_index() {
    let mut state = fixture(2);
    let first = request(&mut state, b"key:0").unwrap();
    let second = request(&mut state, b"key:1").unwrap();
    state.complete_exchange(&second);
    state.fail_exchange(&first, "delivery failed".into());
    let report = state.snapshot();
    assert_eq!(report.matched[0].target_event_index, Some(1));
    assert_eq!(report.unsafe_events[0].target_event_index, Some(0));
    assert!(report.is_dirty());
}
