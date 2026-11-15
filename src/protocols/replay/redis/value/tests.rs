use super::super::*;
use super::*;
use serde_json::json;

pub(in crate::protocols::replay::redis::value) fn record(value: &[u8]) -> RecordedExchange {
    serde_json::from_value(json!({
        "connection_id": Uuid::new_v4(), "sequence":1, "target_host":"redis.test", "target_port":6379,
        "resp_version":2, "database":0,"username":null, "command":"SET",
        "args":[{"encoding":"utf8","data":"erp:membership:1"},{"encoding":"base64","data": STANDARD.encode(value)}, {"encoding":"utf8","data":"EX"},{"encoding":"utf8","data":"900"}],
        "response_kind":"simple_string", "response":{"encoding":"utf8","data":"+OK\r\n"}, "replay_safe":true
    })).unwrap()
}
pub(in crate::protocols::replay::redis::value) fn state(value: &[u8]) -> RedisReplayState {
    let mut state = RedisReplayState::default();
    state
        .register_exchange(
            record(value),
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
    state
}
pub(in crate::protocols::replay::redis::value) fn args(value: &[u8]) -> Vec<Vec<u8>> {
    vec![
        b"erp:membership:1".to_vec(),
        value.to_vec(),
        b"EX".to_vec(),
        b"900".to_vec(),
    ]
}
pub(in crate::protocols::replay::redis::value) fn match_value(
    state: &mut RedisReplayState,
    value: &[u8],
) -> Result<MatchedRedisExchange, crate::protocols::replay::redis::report::CommandMatchDiagnostic> {
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
        "SET",
        &args(value),
    )
}
#[test]
fn automatic_json_maps_keep_values_types_and_duplicate_members_strict() {
    let original = br#"{"B":true,"A":false,"nested":{"b":2,"a":1}}"#;
    let mut state = state(original);
    for bad in [
        br#"{"A":true,"B":true,"nested":{"a":1,"b":2}}"#.as_slice(),
        br#"{"A":false,"B":true}"#,
        br#"{"A":false,"B":"true","nested":{"a":1,"b":2}}"#,
        br#"{"B":false,"B":true,"A":false,"nested":{"b":2,"a":1}}"#,
    ] {
        assert!(match_value(&mut state, bad).is_err());
    }
    let matched = match_value(
        &mut state,
        br#"{"nested":{"a":1,"b":2},"A":false,"B":true}"#,
    )
    .unwrap();
    assert!(matched.rule_ids.is_empty());
    assert_eq!(matched.response, b"+OK\r\n");
    state.complete_exchange(&matched);
    assert!(match_value(&mut state, original).is_err());
    assert_eq!(state.snapshot().matched_count, 1);
}
#[test]
fn arrays_and_unknown_protobuf_keep_exact_values_without_global_formats() {
    for (source, target) in [
        (
            br#"{"ids":[2,1,1]}"#.as_slice(),
            br#"{"ids":[1,2,1]}"#.as_slice(),
        ),
        (b"\x22\x01b\x22\x01a\x28\x01", b"\x22\x01a\x22\x01b\x28\x01"),
        (b"\x08\x01\x10\x02", b"\x10\x02\x08\x01"),
    ] {
        let mut replay = state(source);
        assert!(match_value(&mut replay, target).is_err());
        assert!(match_value(&mut replay, source).is_ok());
    }
}

#[test]
fn only_whole_string_write_values_are_semantic() {
    for (command, index) in [("SET", 1), ("SETNX", 1), ("SETEX", 2), ("PSETEX", 2)] {
        let mut a = vec![
            b"key".to_vec(),
            b"900".to_vec(),
            br#"{"b":2,"a":1}"#.to_vec(),
        ];
        if index == 1 {
            a.remove(1);
        }
        let mut b = a.clone();
        b[index] = br#"{"a":1,"b":2}"#.to_vec();
        assert!(paired_values(command, &a, &b).is_some());
        b[0] = b"other".to_vec();
        assert!(paired_values(command, &a, &b).is_none());
    }
    assert!(paired_values("APPEND", &args(b"{}"), &args(b"{ }")).is_none());
    let mut b = args(b"{ }");
    b[3] = b"901".to_vec();
    assert!(paired_values("SET", &args(b"{}"), &b).is_none());
}
#[test]
fn numeric_key_selectors_share_process_owned_semantics() {
    let selector = RedisValueKeySelector::Numeric {
        prefix: "cache:".into(),
        suffix: ":members".into(),
    };
    assert!(selector.matches(b"cache:001:members"));
    assert!(!selector.matches(b"cache:user:members"));
    assert!(!selector.matches(b"cache::members"));
}

#[test]
fn multi_megabyte_json_string_writes_keep_semantic_comparison() {
    let padding = "x".repeat(2 * 1024 * 1024);
    let source = format!(r#"{{"padding":"{padding}","stable":true}}"#);
    let target = format!(r#"{{"stable":true,"padding":"{padding}"}}"#);
    let mut replay = state(source.as_bytes());
    let matched = match_value(&mut replay, target.as_bytes()).unwrap();
    replay.complete_exchange(&matched);
    assert!(replay.snapshot().unused_case.is_empty());
}
