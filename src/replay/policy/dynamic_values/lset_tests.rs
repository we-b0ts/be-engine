use super::*;
use serde_json::{Value, json};

fn rule() -> DynamicValueRule {
    serde_json::from_value(json!({"id":"text","api":"/blocks","targets":[{"host":"cache.test","port":6379}],
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
            "command":"LSET","key":"blocks:7","argument_index":2,"json_pointer":"/id",
            "when":{"relative_pointer":"../type","equals":"text"},
            "references":[{"json_pointer":"/content_key","template":"content:{value}"}],
            "derived_from":{"json_pointer":"/timestamp","prefix":"text-"}},
        "source_evidence":"Source generates a text identity and preserves its content-key copy in a list element"})).unwrap()
}
fn endpoint() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 6379,
    }
}
fn runtime(rule: DynamicValueRule) -> DynamicValues {
    DynamicValues::new(
        vec![rule],
        BTreeMap::from([("case".into(), "/blocks".into())]),
    )
}
fn text(time: i64) -> Value {
    json!({"type":"text","id":format!("text-{time}"),"timestamp":time,"content_key":format!("content:text-{time}"),"status":"complete"})
}
fn args(value: Value) -> Vec<Vec<u8>> {
    vec![
        b"blocks:7".to_vec(),
        b"-1".to_vec(),
        value.to_string().into_bytes(),
    ]
}

#[test]
fn lset_conditional_capture_preserves_shape_index_bindings_and_unselected_fields() {
    rule().validate().unwrap();
    let runtime = runtime(rule());
    let source = args(text(1000));
    let actual = args(text(2000));
    let checked = runtime
        .redis(Some("case"), &endpoint(), 0, "LSET", &source, &actual)
        .unwrap()
        .unwrap();
    // The identity owns /id and /content_key; timestamp retains its independent owner.
    let left: Value = serde_json::from_slice(&checked.source[2]).unwrap();
    let right: Value = serde_json::from_slice(&checked.actual[2]).unwrap();
    assert_eq!(left["id"], right["id"]);
    assert_eq!(left["content_key"], right["content_key"]);
    assert_eq!(left["timestamp"], 1000);
    assert_eq!(right["timestamp"], 2000);
    assert_eq!(checked.source[1], b"-1");
    runtime.commit("case", checked.decision).unwrap();
    assert!(
        runtime
            .redis(
                Some("case"),
                &endpoint(),
                0,
                "LSET",
                &source,
                &args(text(2001))
            )
            .unwrap()
            .is_err()
    );
    for change in [
        "index", "key", "extra", "missing", "type", "copy", "derived",
    ] {
        let mut bad = actual.clone();
        match change {
            "index" => bad[1] = b"0".to_vec(),
            "key" => bad[0] = b"blocks:8".to_vec(),
            "extra" => bad.push(b"extra".to_vec()),
            "missing" => {
                bad.pop();
            }
            _ => {
                let mut body = text(2000);
                match change {
                    "type" => body["type"] = json!("thinking"),
                    "copy" => body["content_key"] = json!("wrong"),
                    _ => body["id"] = json!("text-2001"),
                }
                bad[2] = body.to_string().into_bytes();
            }
        }
        assert!(
            runtime
                .redis(Some("case"), &endpoint(), 0, "LSET", &source, &bad)
                .unwrap()
                .is_err(),
            "{change}"
        );
    }
    let mut changed = text(2000);
    changed["status"] = json!("different");
    let checked = runtime
        .redis(
            Some("case"),
            &endpoint(),
            0,
            "LSET",
            &source,
            &args(changed),
        )
        .unwrap()
        .unwrap();
    assert_ne!(checked.source, checked.actual);
}

#[test]
fn lset_list_index_cannot_be_normalized_as_an_identity_reference() {
    let mut definition = serde_json::to_value(rule()).unwrap();
    definition["capture"] = json!({"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,
        "command":"SET","key":"current","argument_index":1});
    let runtime = runtime(serde_json::from_value(definition).unwrap());
    let captured = runtime
        .redis(
            Some("case"),
            &endpoint(),
            0,
            "SET",
            &[b"current".to_vec(), b"0".to_vec()],
            &[b"current".to_vec(), b"1".to_vec()],
        )
        .unwrap()
        .unwrap();
    runtime.commit("case", captured.decision).unwrap();
    let source = vec![
        b"blocks:7".to_vec(),
        b"0".to_vec(),
        br#"{"id":"0"}"#.to_vec(),
    ];
    let actual = vec![
        b"blocks:7".to_vec(),
        b"0".to_vec(),
        br#"{"id":"1"}"#.to_vec(),
    ];
    let checked = runtime
        .redis(Some("case"), &endpoint(), 0, "LSET", &source, &actual)
        .unwrap()
        .unwrap();
    assert_eq!(checked.source, checked.actual);
    let mut moved = actual;
    moved[1] = b"1".to_vec();
    assert!(
        runtime
            .redis(Some("case"), &endpoint(), 0, "LSET", &source, &moved)
            .unwrap()
            .is_err()
    );
}

#[test]
fn lset_source_and_candidates_use_only_element_slot_two() {
    let runtime = runtime(rule());
    runtime.observe_redis(
        "case",
        &endpoint(),
        0,
        "LSET",
        &args(text(1000)),
        &args(text(2000)),
    );
    assert_eq!(runtime.capture_candidates().len(), 3);
    assert!(runtime.capture_candidates().iter().all(|c| matches!(
        c.capture,
        DynamicValueCapture::Redis {
            argument_index: 2,
            ..
        }
    )));
    let mut event = json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,"database":0,
        "command":"LSET","replay_safe":true,"response":{"encoding":"utf8","data":"+OK\r\n"},
        "args":args(text(1000)).iter().map(|v|json!({"encoding":"utf8","data":String::from_utf8(v.clone()).unwrap()})).collect::<Vec<_>>()});
    assert_eq!(
        recorded_capture(&rule().capture, rule().value_type, &event)
            .unwrap()
            .unwrap()
            .value,
        "text-1000"
    );
    event["args"]
        .as_array_mut()
        .unwrap()
        .push(json!({"encoding":"utf8","data":"extra"}));
    assert!(recorded_capture(&rule().capture, rule().value_type, &event).is_err());
    for index in [0, 1, 3] {
        let mut definition = serde_json::to_value(rule()).unwrap();
        definition["capture"]["argument_index"] = json!(index);
        assert!(
            serde_json::from_value::<DynamicValueRule>(definition)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
