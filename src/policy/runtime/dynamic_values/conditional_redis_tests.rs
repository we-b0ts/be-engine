use super::*;
use serde_json::{Value, json};

fn rule() -> DynamicValueRule {
    serde_json::from_value(json!({"id":"text","api":"/blocks","targets":[{"host":"cache.test","port":6379}],
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
            "command":"RPUSH","key":"blocks:7","argument_index":1,"json_pointer":"/id",
            "when":{"relative_pointer":"../type","equals":"text"},
            "references":[{"json_pointer":"/content_key","template":"content:{value}"}],
            "derived_from":{"json_pointer":"/timestamp","prefix":"text-"}},
        "source_evidence":"Source generates text IDs from milliseconds and uses the bound ID in subsequent Redis keys"})).unwrap()
}
fn endpoint() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 6379,
    }
}
fn runtime() -> DynamicValues {
    DynamicValues::new(
        vec![rule()],
        BTreeMap::from([("case".into(), "/blocks".into())]),
    )
}
fn text(time: i64) -> Value {
    json!({"type":"text","id":format!("text-{time}"),"timestamp":time,"content_key":format!("content:text-{time}"),"content":""})
}
fn args(value: &Value) -> Vec<Vec<u8>> {
    vec![b"blocks:7".to_vec(), value.to_string().into_bytes()]
}

#[test]
fn conditional_redis_identity_keeps_inactive_blocks_strict_and_binds_only_active_captures() {
    rule().validate().unwrap();
    let runtime = runtime();
    for kind in ["thinking", "tool"] {
        let value = json!({"type":kind,"id":format!("{kind}-fresh"),"timestamp":1000});
        let compared = runtime
            .redis(
                Some("case"),
                &endpoint(),
                0,
                "RPUSH",
                &args(&value),
                &args(&value),
            )
            .unwrap()
            .unwrap();
        assert!(compared.decision.pairs.is_empty());
        assert_eq!(compared.source, compared.actual);
        let mut changed = value.clone();
        changed["id"] = "different".into();
        let checked = runtime
            .redis(
                Some("case"),
                &endpoint(),
                0,
                "RPUSH",
                &args(&value),
                &args(&changed),
            )
            .unwrap()
            .unwrap();
        assert_ne!(checked.source, checked.actual);
    }
    let compared = runtime
        .redis(
            Some("case"),
            &endpoint(),
            0,
            "RPUSH",
            &args(&text(1000)),
            &args(&text(2000)),
        )
        .unwrap()
        .unwrap();
    assert_eq!(compared.decision.pairs.len(), 1);
    runtime.commit("case", compared.decision).unwrap();
    // References have no JSON type field: the existing binding still applies.
    let left = vec![b"content:text-1000".to_vec(), b"hello".to_vec()];
    let right = vec![b"content:text-2000".to_vec(), b"hello".to_vec()];
    let reference = runtime
        .redis(Some("case"), &endpoint(), 0, "APPEND", &left, &right)
        .unwrap()
        .unwrap();
    assert_eq!(reference.source, reference.actual);
    assert_eq!(runtime.rule_reports()[0].matches, 1);
}

#[test]
fn conditional_redis_identity_rejects_type_switches_corruption_derivation_and_binding_changes() {
    let runtime = runtime();
    for (source, target) in [
        (
            text(1000),
            json!({"type":"thinking","id":"thinking-fresh","timestamp":2000}),
        ),
        (json!({"type":"thinking","id":"same"}), text(2000)),
        (json!({"id":"text-1000"}), text(2000)),
        (json!({"type":null,"id":"text-1000"}), text(2000)),
        (
            text(1000),
            json!({"type":"text","id":"text-2001","timestamp":2000,"content_key":"content:text-2001"}),
        ),
    ] {
        assert!(
            runtime
                .redis(
                    Some("case"),
                    &endpoint(),
                    0,
                    "RPUSH",
                    &args(&source),
                    &args(&target)
                )
                .unwrap()
                .is_err()
        );
    }
    let duplicate = vec![
        b"blocks:7".to_vec(),
        br#"{"type":"text","type":"thinking","id":"x"}"#.to_vec(),
    ];
    assert!(
        runtime
            .redis(
                Some("case"),
                &endpoint(),
                0,
                "RPUSH",
                &duplicate,
                &duplicate
            )
            .unwrap()
            .is_err()
    );
    let first = runtime
        .redis(
            Some("case"),
            &endpoint(),
            0,
            "RPUSH",
            &args(&text(1000)),
            &args(&text(2000)),
        )
        .unwrap()
        .unwrap();
    runtime.commit("case", first.decision).unwrap();
    for (source, target) in [(text(1000), text(2001)), (text(1001), text(2000))] {
        assert!(
            runtime
                .redis(
                    Some("case"),
                    &endpoint(),
                    0,
                    "RPUSH",
                    &args(&source),
                    &args(&target)
                )
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn conditional_redis_source_applicability_counts_only_selected_payloads() {
    for (value, expected) in [
        (json!({"type":"thinking","id":"thinking-fresh"}), false),
        (text(1000), true),
    ] {
        let event = json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,"database":0,
            "command":"RPUSH","replay_safe":true,"args":[{"encoding":"utf8","data":"blocks:7"},{"encoding":"utf8","data":value.to_string()}],
            "response":{"encoding":"utf8","data":":1\r\n"}});
        assert_eq!(
            recorded_capture(&rule().capture, rule().value_type, &event)
                .unwrap()
                .is_some(),
            expected
        );
    }
}

#[test]
fn conditional_capture_without_copies_changes_only_the_declared_pointer() {
    let mut definition = serde_json::to_value(rule()).unwrap();
    definition["capture"]
        .as_object_mut()
        .unwrap()
        .remove("references");
    definition["capture"]
        .as_object_mut()
        .unwrap()
        .remove("derived_from");
    let rule: DynamicValueRule = serde_json::from_value(definition).unwrap();
    rule.validate().unwrap();
    let runtime = DynamicValues::new(
        vec![rule],
        BTreeMap::from([("case".into(), "/blocks".into())]),
    );
    let source = args(&json!({"type":"text","id":"old","stable":"old"}));
    let target = args(&json!({"type":"text","id":"new","stable":"old"}));
    let checked = runtime
        .redis(Some("case"), &endpoint(), 0, "RPUSH", &source, &target)
        .unwrap()
        .unwrap();
    assert_eq!(checked.source, checked.actual);
    let changed = args(&json!({"type":"text","id":"new","stable":"new"}));
    let checked = runtime
        .redis(Some("case"), &endpoint(), 0, "RPUSH", &source, &changed)
        .unwrap()
        .unwrap();
    assert_ne!(checked.source, checked.actual);
    // A pending capture never authorizes changes to another RPUSH element.
    let mut source = source;
    source.push(b"old".to_vec());
    let mut target = target;
    target.push(b"new".to_vec());
    let checked = runtime
        .redis(Some("case"), &endpoint(), 0, "RPUSH", &source, &target)
        .unwrap()
        .unwrap();
    assert_ne!(checked.source, checked.actual);
}
