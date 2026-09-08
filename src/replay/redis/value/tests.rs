use super::super::*;
use super::*;
use crate::replay::policy::{ProtobufFieldPath, ProtobufRepeatedElementType};
use serde_json::json;

pub(in crate::replay::redis::value) fn record(value: &[u8]) -> RecordedExchange {
    serde_json::from_value(json!({
        "connection_id": Uuid::new_v4(), "sequence":1, "target_host":"redis.test", "target_port":6379,
        "resp_version":2, "database":0,"username":null, "command":"SET",
        "args":[{"encoding":"utf8","data":"erp:membership:1"},{"encoding":"base64","data": STANDARD.encode(value)}, {"encoding":"utf8","data":"EX"},{"encoding":"utf8","data":"900"}],
        "response_kind":"simple_string", "response":{"encoding":"utf8","data":"+OK\r\n"}, "replay_safe":true
    })).unwrap()
}
pub(in crate::replay::redis::value) fn state(value: &[u8]) -> RedisReplayState {
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
pub(in crate::replay::redis::value) fn args(value: &[u8]) -> Vec<Vec<u8>> {
    vec![
        b"erp:membership:1".to_vec(),
        value.to_vec(),
        b"EX".to_vec(),
        b"900".to_vec(),
    ]
}
pub(in crate::replay::redis::value) fn match_value(
    state: &mut RedisReplayState,
    value: &[u8],
) -> Result<MatchedRedisExchange, crate::replay::report::command::CommandMatchDiagnostic> {
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
pub(in crate::replay::redis::value) fn selector() -> RedisUnorderedSelector {
    RedisUnorderedSelector {
        host: "redis.test".into(),
        port: 6379,
        key: RedisValueKeySelector::Affix {
            prefix: "erp:membership:".into(),
            suffix: String::new(),
        },
        field: RedisUnorderedField::Json {
            pointer: "/ids".into(),
        },
    }
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
fn explicit_arrays_preserve_multiplicity_siblings_and_endpoint_key_scope() {
    let original = br#"{"ids":[2,1,1],"ordered":[1,2]}"#;
    let target = br#"{"ids":[1,2,1],"ordered":[1,2]}"#;
    let mut state = state(original);
    assert!(match_value(&mut state, target).is_err());
    let mut rule = ValueRule {
        id: "membership".into(),
        selector: selector(),
    };
    rule.selector.port = 6380;
    state.value_rules = vec![rule.clone()];
    assert!(match_value(&mut state, target).is_err());
    rule.selector.port = 6379;
    rule.selector.host = "other.test".into();
    state.value_rules = vec![rule.clone()];
    assert!(match_value(&mut state, target).is_err());
    rule.selector.host = "redis.test".into();
    rule.selector.key = RedisValueKeySelector::Exact {
        value: "wrong-key".into(),
    };
    state.value_rules = vec![rule.clone()];
    assert!(match_value(&mut state, target).is_err());
    state.value_rules = vec![ValueRule {
        id: "membership".into(),
        selector: selector(),
    }];
    for bad in [
        br#"{"ids":[1,2,2],"ordered":[1,2]}"#.as_slice(),
        br#"{"ids":[1,2,1],"ordered":[2,1]}"#,
        br#"{"ids":[1,2],"ordered":[1,2]}"#,
    ] {
        assert!(match_value(&mut state, bad).is_err());
    }
    let matched = match_value(&mut state, target).unwrap();
    assert_eq!(matched.rule_ids, ["membership"]);
}
#[test]
fn json_array_wildcards_and_root_are_explicit() {
    let a = br#"{"groups":[{"ids":[2,1]},{"ids":[4,3]}]}"#;
    let b = br#"{"groups":[{"ids":[1,2]},{"ids":[3,4]}]}"#;
    assert!(compare(
        a,
        b,
        &[RedisUnorderedField::Json {
            pointer: "/groups/*/ids".into()
        }]
    ));
    assert!(!compare(b"[2,1,1]", b"[1,2,1]", &[]));
    assert!(compare(
        b"[2,1,1]",
        b"[1,2,1]",
        &[RedisUnorderedField::Json {
            pointer: String::new()
        }]
    ));
}
#[test]
fn protobuf_repeated_values_require_typed_paths_and_preserve_siblings() {
    // Field 4 tag is also the ASCII quote: it must not be mistaken for malformed JSON.
    let a = b"\x22\x01b\x22\x01a\x28\x01";
    let b = b"\x22\x01a\x22\x01b\x28\x01";
    let field = RedisUnorderedField::Protobuf {
        field_path: ProtobufFieldPath(vec![4]),
        element_type: ProtobufRepeatedElementType::String,
        display_path: "value.ids".into(),
    };
    assert!(!compare(a, b, &[]));
    assert!(compare(a, b, std::slice::from_ref(&field)));
    assert!(!compare(
        a,
        b"\x22\x01a\x22\x01b\x28\x02",
        std::slice::from_ref(&field)
    ));
    assert!(!compare(
        a,
        b"\x22\x01a\x22\x01a\x28\x01",
        std::slice::from_ref(&field)
    ));
    let wrong = RedisUnorderedField::Protobuf {
        field_path: ProtobufFieldPath(vec![4]),
        element_type: ProtobufRepeatedElementType::Message,
        display_path: "value.ids".into(),
    };
    assert!(!compare(a, b, &[wrong]));
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
