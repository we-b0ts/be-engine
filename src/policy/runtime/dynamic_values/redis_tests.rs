//! Redis capture selectors retain exact keys, bounded witnesses and case-local bindings.
use super::*;
use serde_json::{Value, json};

fn rule(key: Value) -> DynamicValueRule {
    serde_json::from_value(json!({
        "id":"name", "api":"/items", "targets":[{"host":"cache.test","port":6379}],
        "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},
            "database":0,"command":"SET","key":key,"argument_index":1,"json_pointer":"/name"},
        "source_evidence":"Generator:create produces a name reused in later dependency requests"
    }))
    .unwrap()
}

fn args(key: &str, name: &str, stable: u64) -> Vec<Vec<u8>> {
    vec![
        key.as_bytes().to_vec(),
        json!({"name":name,"stable":stable})
            .to_string()
            .into_bytes(),
        b"EX".to_vec(),
        b"60".to_vec(),
    ]
}

fn target() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 6379,
    }
}

fn runtime(rule: DynamicValueRule) -> DynamicValues {
    DynamicValues::new(
        vec![rule],
        BTreeMap::from([
            ("case".into(), "/items".into()),
            ("other".into(), "/items".into()),
        ]),
    )
}

fn event(key: &str) -> Value {
    json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,
        "database":0,"command":"SET","replay_safe":true,
        "args":[{"encoding":"utf8","data":key},{"encoding":"utf8","data":"{\"name\":\"source-name\",\"stable\":1}"}],
        "response":{"encoding":"utf8","data":"+OK\r\n"}})
}

#[test]
fn rpush_integer_capture_is_typed_case_local_and_keeps_other_fields_exact() {
    let mut spec = serde_json::to_value(rule(json!("events"))).unwrap();
    spec["value_type"] = json!("integer");
    spec["capture"]["command"] = json!("RPUSH");
    spec["capture"]["json_pointer"] = json!("/id");
    let rule: DynamicValueRule = serde_json::from_value(spec).unwrap();
    rule.validate().unwrap();
    let runtime = runtime(rule.clone());
    let values = |body: &str| vec![b"events".to_vec(), body.as_bytes().to_vec()];
    let source = values(r#"{ "id": 1, "stable": 7 }"#);
    let actual = values(r#"{"id":9,"stable":7}"#);
    let normalized = runtime
        .redis(Some("case"), &target(), 0, "RPUSH", &source, &actual)
        .unwrap()
        .unwrap();
    assert_eq!(normalized.source, normalized.actual);
    runtime.commit("case", normalized.decision).unwrap();
    assert!(
        runtime
            .redis(
                Some("case"),
                &target(),
                0,
                "RPUSH",
                &source,
                &values(r#"{"id":10,"stable":7}"#)
            )
            .unwrap()
            .is_err()
    );
    for body in [
        r#"{"id":"9","stable":7}"#,
        r#"{"id":9.0,"stable":7}"#,
        r#"{"id":9,"id":10,"stable":7}"#,
        r#"{"stable":7}"#,
    ] {
        assert!(
            runtime
                .redis(Some("case"), &target(), 0, "RPUSH", &source, &values(body))
                .unwrap()
                .is_err()
        );
    }
    let normalized = runtime
        .redis(
            Some("case"),
            &target(),
            0,
            "RPUSH",
            &source,
            &values(r#"{"id":9,"stable":9}"#),
        )
        .unwrap()
        .unwrap();
    assert_ne!(normalized.source, normalized.actual);
    assert!(
        runtime
            .redis(
                Some("other"),
                &target(),
                0,
                "RPUSH",
                &source,
                &values(r#"{"id":10,"stable":7}"#)
            )
            .unwrap()
            .is_ok()
    );
    let mut recorded = event("events");
    recorded["command"] = json!("RPUSH");
    recorded["args"][1]["data"] = json!(r#"{"id":1,"stable":7}"#);
    assert_eq!(
        source::from_event(&rule.capture, rule.value_type, &recorded)
            .unwrap()
            .unwrap()
            .value,
        "1"
    );
}

#[test]
fn rpush_discovery_reports_each_typed_field_without_exposing_values() {
    let runtime = runtime(rule(json!("events")));
    let values = |body: &str| vec![b"events".to_vec(), body.as_bytes().to_vec()];
    runtime.observe_redis(
        "case",
        &target(),
        0,
        "RPUSH",
        &values(r#"{"id":1,"timestamp":1000,"stable":7}"#),
        &values(r#"{"id":9,"timestamp":2000,"stable":7}"#),
    );
    let candidates = runtime.capture_candidates();
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates
            .iter()
            .all(|c| c.value_type == DynamicValueType::Integer)
    );
    assert!(
        !serde_json::to_string(&candidates)
            .unwrap()
            .contains("\"timestamp\":2000")
    );
}

#[test]
fn exact_affix_and_numeric_selectors_round_trip_and_select_recorded_keys() {
    for (selector, matching, rejected) in [
        (json!("task:12:status"), "task:12:status", "task:13:status"),
        (
            json!({"prefix":"task:"}),
            "task:12:status",
            "other:12:status",
        ),
        (
            json!({"suffix":":status"}),
            "task:12:status",
            "task:12:other",
        ),
        (
            json!({"prefix":"task:","suffix":":status"}),
            "task:12:status",
            "task:12:other",
        ),
        (
            json!({"prefix":"task:","suffix":":status","numeric":true}),
            "task:12:status",
            "task:abc:status",
        ),
        (json!({"prefix":"task:","numeric":true}), "task:12", "task:"),
    ] {
        let rule = rule(selector.clone());
        rule.validate().unwrap();
        let rendered = serde_json::to_value(&rule).unwrap();
        assert_eq!(rendered["capture"]["key"], selector);
        assert_eq!(
            serde_json::from_value::<DynamicValueRule>(rendered).unwrap(),
            rule
        );
        for (key, selected) in [(matching, true), (rejected, false)] {
            let source = source::from_event(&rule.capture, rule.value_type, &event(key)).unwrap();
            assert_eq!(source.is_some(), selected, "{selector}: {key}");
            let runtime = runtime(rule.clone());
            let normalized = runtime.redis(
                Some("case"),
                &target(),
                0,
                "SET",
                &args(key, "old", 1),
                &args(key, "new", 1),
            );
            assert_eq!(normalized.is_some(), selected);
            if let Some(normalized) = normalized {
                let normalized = normalized.unwrap();
                assert_eq!(normalized.source, normalized.actual);
            }
        }
    }
    // A star remains a literal in the original string syntax.
    let literal = rule(json!("task:*"));
    assert!(
        source::from_event(&literal.capture, literal.value_type, &event("task:12"))
            .unwrap()
            .is_none()
    );
    assert!(
        source::from_event(&literal.capture, literal.value_type, &event("task:*"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn selectors_reject_empty_oversized_and_unsupported_patterns() {
    for selector in [
        json!(""),
        json!({}),
        json!({"prefix":""}),
        json!({"regex":"^task:.*$"}),
        json!({"prefix":"task:","unknown":true}),
        json!({"kind":"exact","value":"task:1","prefix":"task:"}),
        json!({"prefix":"x".repeat(1025)}),
        json!("x".repeat(1025)),
    ] {
        assert!(serde_json::from_value::<DynamicValueRule>(json!({
            "id":"name","api":"/items","targets":[{"host":"cache.test","port":6379}],
            "capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},
                "database":0,"command":"SET","key":selector,"argument_index":1},"source_evidence":"Generator:create chooses a name"
        })).is_err(), "{selector}");
    }
    let rule = rule(json!({"prefix":"task:"}));
    let oversized = format!("task:{}", "1".repeat(1020));
    assert!(
        source::from_event(&rule.capture, rule.value_type, &event(&oversized))
            .unwrap()
            .is_none()
    );
    assert!(
        runtime(rule)
            .redis(
                Some("case"),
                &target(),
                0,
                "SET",
                &args(&oversized, "old", 1),
                &args(&oversized, "new", 1)
            )
            .is_none()
    );
}

#[test]
fn prefix_capture_keeps_complete_keys_options_database_and_unselected_json_exact() {
    let runtime = runtime(rule(json!({"prefix":"task:","numeric":true})));
    let source = args("task:12", "old", 1);
    let actual = args("task:12", "new", 1);
    assert!(
        runtime
            .redis(
                Some("case"),
                &target(),
                0,
                "SET",
                &source,
                &args("task:13", "new", 1)
            )
            .unwrap()
            .is_err()
    );
    for (case, endpoint, db, command) in [
        (None, target(), 0, "SET"),
        (Some("case"), target(), 1, "SET"),
        (Some("case"), target(), 0, "HSET"),
        (
            Some("case"),
            TargetKey {
                host: "other.test".into(),
                port: 6379,
            },
            0,
            "SET",
        ),
    ] {
        assert!(
            runtime
                .redis(case, &endpoint, db, command, &source, &actual)
                .is_none()
        );
    }
    let mut extra = actual.clone();
    extra.push(b"NX".to_vec());
    assert!(
        runtime
            .redis(Some("case"), &target(), 0, "SET", &source, &extra)
            .unwrap()
            .is_err()
    );
    let mut option = actual.clone();
    option[3] = b"61".to_vec();
    for actual in [args("task:12", "new", 2), option] {
        let compared = runtime
            .redis(Some("case"), &target(), 0, "SET", &source, &actual)
            .unwrap()
            .unwrap();
        assert_ne!(compared.source, compared.actual);
    }
    let compared = runtime
        .redis(Some("case"), &target(), 0, "SET", &source, &actual)
        .unwrap()
        .unwrap();
    assert_eq!(compared.source[0], b"task:12");
    assert_eq!(compared.source, compared.actual);
    runtime.commit("case", compared.decision).unwrap();
    assert!(
        runtime
            .redis(
                Some("case"),
                &target(),
                0,
                "SET",
                &args("task:13", "old", 1),
                &args("task:13", "different", 1)
            )
            .unwrap()
            .is_err()
    );
    assert!(
        runtime
            .redis(
                Some("case"),
                &target(),
                0,
                "SET",
                &args("task:13", "different", 1),
                &args("task:13", "new", 1)
            )
            .unwrap()
            .is_err()
    );
    assert!(
        runtime
            .redis(
                Some("other"),
                &target(),
                0,
                "SET",
                &source,
                &args("task:12", "different", 1)
            )
            .unwrap()
            .is_ok()
    );
    runtime.begin_case("case");
    assert!(
        runtime
            .redis(
                Some("case"),
                &target(),
                0,
                "SET",
                &source,
                &args("task:12", "different", 1)
            )
            .unwrap()
            .is_ok()
    );
}

#[test]
fn patterned_capture_supports_hset_and_reports_source_applicability() {
    let mut rule = rule(json!({"prefix":"task:","suffix":":status","numeric":true}));
    if let DynamicValueCapture::Redis {
        command,
        argument_index,
        ..
    } = &mut rule.capture
    {
        *command = "HSET".into();
        *argument_index = 2;
    }
    rule.validate().unwrap();
    let runtime = runtime(rule);
    let source = vec![
        b"task:12:status".to_vec(),
        b"field".to_vec(),
        br#"{"name":"old","stable":1}"#.to_vec(),
    ];
    let actual = vec![
        b"task:12:status".to_vec(),
        b"field".to_vec(),
        br#"{"name":"new","stable":1}"#.to_vec(),
    ];
    let mut event = event("task:12:status");
    event["command"] = json!("HSET");
    event["args"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!({"encoding":"utf8","data":"field"}));
    runtime
        .observe_source("case", &serde_json::to_vec(&event).unwrap())
        .unwrap();
    assert!(runtime.rule_reports()[0].applicable);
    let compared = runtime
        .redis(Some("case"), &target(), 0, "HSET", &source, &actual)
        .unwrap()
        .unwrap();
    assert_eq!(compared.source, compared.actual);
    runtime.commit("case", compared.decision).unwrap();
    assert_eq!(runtime.rule_reports()[0].matches, 1);
}

#[test]
fn overlapping_key_patterns_cannot_own_the_same_capture_location() {
    let first = rule(json!({"prefix":"task:"}));
    for (selector, rejected) in [
        (json!("task:12"), true),
        (json!({"suffix":":status"}), true),
        (json!({"prefix":"task:","numeric":true}), true),
        (json!({"prefix":"other:"}), false),
    ] {
        let mut second = rule(selector);
        second.id = "second".into();
        assert_eq!(
            validate(&[first.clone(), second.clone()]).is_err(),
            rejected
        );
        second.api = "/other".into();
        validate(&[first.clone(), second.clone()]).unwrap();
        second.api = first.api.clone();
        if let DynamicValueCapture::Redis { json_pointer, .. } = &mut second.capture {
            *json_pointer = Some("/other".into());
        }
        validate(&[first.clone(), second]).unwrap();
    }
}

#[test]
fn request_contract_overlap_checks_key_patterns_and_json_locations() {
    for (selector, rejected) in [
        (json!({"prefix":"task:","numeric":true}), true),
        (json!({"prefix":"other:"}), false),
    ] {
        let mut document: super::super::config::ReplayPolicyDocument =
            serde_yaml::from_str("version: 3\nexpected_response: assertions_only\n").unwrap();
        document.dynamic_values = vec![rule(selector)];
        document.dependency_rules = vec![serde_json::from_value(json!({"id":"request-time","protocol":"redis",
            "case":{"method":"POST","path":"/items"},"target":{"host":"cache.test","port":6379},
            "source_evidence":"Generator:create writes a current timestamp",
            "redis":{"database":0,"key":{"prefix":"task:"},"commands":[{"command":"SET",
                "argument_values":{"1":{"json":{"/at":{"time":"preserve_relative","format":"unix_seconds"}}}}}]}
        })).unwrap()];
        super::super::request_contract::validate_overlaps(&document).unwrap();
        let DynamicValueCapture::Redis { json_pointer, .. } =
            &mut document.dynamic_values[0].capture
        else {
            unreachable!()
        };
        *json_pointer = Some("/at".into());
        assert_eq!(
            super::super::request_contract::validate_overlaps(&document).is_err(),
            rejected
        );
    }
}
