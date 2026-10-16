use super::*;
use serde_json::json;

fn condition(pointer: &str, value: JsonCondition) -> CaseCondition {
    CaseCondition {
        request_body_json: BTreeMap::from([(pointer.to_owned(), value)]),
    }
}

fn request(body: Value) -> Value {
    raw_request(&serde_json::to_string(&body).unwrap(), "utf8")
}

fn raw_request(data: &str, encoding: &str) -> Value {
    json!({"body": {
        "encoding": encoding, "data": data, "truncated": false, "decode_error": null
    }})
}

#[test]
fn condition_schema_requires_one_known_operator_per_exact_pointer() {
    let value = json!({"request_body_json": {
        "/event_type": {"equals": "session.created"},
        "/data/reused": {"not_equals": true}
    }});
    let parsed: CaseCondition = serde_json::from_value(value.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    for invalid in [
        json!({"request_body_json": {"/event_type": {}}}),
        json!({"request_body_json": {"/event_type": {"equals": "a", "not_equals": "b"}}}),
        json!({"request_body_json": {"/event_type": {"contains": "created"}}}),
        json!({"request_body_json": {"/event_type": "session.created"}}),
        json!({"request_body_json": {"/event_type": {"equals": "a"}}, "unexpected": true}),
    ] {
        assert!(serde_json::from_value::<CaseCondition>(invalid).is_err());
    }
}

#[test]
fn yaml_condition_maps_round_trip_without_enum_tags_or_ambiguous_operators() {
    let input = "request_body_json:\n  /event_type: {equals: session.created}\n  /data/reused: {not_equals: true}\n";
    let parsed: CaseCondition = serde_yaml::from_str(input).unwrap();
    parsed.validate().unwrap();
    let rendered = serde_yaml::to_string(&parsed).unwrap();
    assert!(!rendered.contains("!equals"));
    assert!(!rendered.contains("!not_equals"));
    assert_eq!(
        serde_yaml::from_str::<CaseCondition>(&rendered).unwrap(),
        parsed
    );
    assert_eq!(
        serde_yaml::from_str::<Value>(&rendered).unwrap(),
        json!({"request_body_json": {
            "/event_type": {"equals": "session.created"},
            "/data/reused": {"not_equals": true}
        }})
    );
    for invalid in [
        "request_body_json:\n  /event_type: {equals: a, not_equals: b}\n",
        "request_body_json:\n  /event_type: {contains: created}\n",
        "request_body_json:\n  /event_type: {equals: a, unexpected: true}\n",
        "request_body_json:\n  /event_type: {equals: a}\nunexpected: true\n",
    ] {
        assert!(serde_yaml::from_str::<CaseCondition>(invalid).is_err());
    }
}

#[test]
fn condition_validation_bounds_fields_pointers_and_scalar_values() {
    let mut fields = BTreeMap::new();
    let empty = CaseCondition {
        request_body_json: fields.clone(),
    };
    assert!(empty.validate().is_err());
    for i in 0..16 {
        fields.insert(format!("/field{i}"), JsonCondition::Equals(json!(i)));
    }
    CaseCondition {
        request_body_json: fields.clone(),
    }
    .validate()
    .unwrap();
    fields.insert("/extra".into(), JsonCondition::NotEquals(json!(false)));
    assert!(
        CaseCondition {
            request_body_json: fields
        }
        .validate()
        .is_err()
    );
    for pointer in ["", "event_type", "/items/*/type", "/bad~2escape"] {
        assert!(
            condition(pointer, JsonCondition::Equals(json!("created")))
                .validate()
                .is_err(),
            "{pointer:?}"
        );
    }
    for value in [Value::Null, json!([]), json!({}), json!("x".repeat(1025))] {
        for operator in [JsonCondition::Equals, JsonCondition::NotEquals] {
            assert!(
                condition("/field", operator(value.clone()))
                    .validate()
                    .is_err()
            );
        }
    }
    for value in [json!(""), json!("x".repeat(1024)), json!(false), json!(7)] {
        condition("/field", JsonCondition::Equals(value))
            .validate()
            .unwrap();
    }
}

#[test]
fn both_operators_require_present_scalars_of_the_declared_json_type() {
    for (expected, equal, different, wrong_type) in [
        (json!("created"), json!("created"), json!("delta"), json!(1)),
        (json!(true), json!(true), json!(false), json!("true")),
        (json!(7), json!(7), json!(8), json!("7")),
    ] {
        let equals = condition("/field", JsonCondition::Equals(expected.clone()));
        let not_equals = condition("/field", JsonCondition::NotEquals(expected));
        assert!(equals.matches_request(&request(json!({"field": equal.clone()}))));
        assert!(!not_equals.matches_request(&request(json!({"field": equal}))));
        assert!(!equals.matches_request(&request(json!({"field": different.clone()}))));
        assert!(not_equals.matches_request(&request(json!({"field": different}))));
        for body in [
            json!({}),
            json!({"field": wrong_type}),
            json!({"field": null}),
            json!({"field": []}),
            json!({"field": {"value": "created"}}),
        ] {
            assert!(!equals.matches_request(&request(body.clone())));
            assert!(!not_equals.matches_request(&request(body)));
        }
    }
}

#[test]
fn predicates_use_and_semantics_and_exact_escaped_pointers_for_both_encodings() {
    let selected = CaseCondition {
        request_body_json: BTreeMap::from([
            (
                "/event_type".into(),
                JsonCondition::Equals(json!("item.delta")),
            ),
            ("/data/enabled".into(), JsonCondition::Equals(json!(true))),
            ("/a~1b/~0field".into(), JsonCondition::NotEquals(json!(2))),
        ]),
    };
    selected.validate().unwrap();
    let body = json!({"event_type": "item.delta",
        "data": {"enabled": true, "type": "item.created"}, "a/b": {"~field": 3}});
    assert!(selected.matches_request(&request(body.clone())));
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&body).unwrap());
    assert!(selected.matches_request(&raw_request(&encoded, "base64")));
    for (pointer, replacement) in [
        ("/event_type", json!("item.created")),
        ("/data/enabled", json!(false)),
        ("/a~1b/~0field", json!(2)),
        ("/a~1b/~0field", json!("3")),
    ] {
        let mut changed = body.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(!selected.matches_request(&request(changed)), "{pointer}");
    }
}

#[test]
fn incomplete_invalid_or_oversized_source_bodies_never_enable_either_operator() {
    let raw = r#"{"event_type":"session.created"}"#;
    let valid = raw_request(raw, "utf8");
    let mut invalid = vec![
        json!({}),
        json!({"body": null}),
        json!({"body": {"encoding": "utf8"}}),
        json!({"body": {"data": raw}}),
        raw_request(raw, "unknown"),
        raw_request("not base64!", "base64"),
        raw_request(r#"{"event_type":"session.created""#, "utf8"),
        raw_request(&format!("{raw} trailing"), "utf8"),
        raw_request(
            r#"{"event_type":"session.created","event_type":"item.delta"}"#,
            "utf8",
        ),
        raw_request(
            r#"{"event_type":"session.created","nested":{"a":1,"a":2}}"#,
            "utf8",
        ),
    ];
    for (field, value) in [
        ("truncated", json!(true)),
        ("truncated", json!(null)),
        ("truncated", json!("false")),
        ("decode_error", json!("invalid request body")),
        ("decode_error", json!(false)),
    ] {
        let mut changed = valid.clone();
        changed["body"][field] = value;
        invalid.push(changed);
    }
    let oversized = serde_json::to_vec(&json!({
        "event_type": "session.created", "padding": "x".repeat(1024 * 1024)
    }))
    .unwrap();
    invalid.push(raw_request(
        std::str::from_utf8(&oversized).unwrap(),
        "utf8",
    ));
    invalid.push(raw_request(
        &base64::engine::general_purpose::STANDARD.encode(&oversized),
        "base64",
    ));
    for operator in [JsonCondition::Equals, JsonCondition::NotEquals] {
        let selected = condition("/event_type", operator(json!("session.created")));
        for artifact in &invalid {
            assert!(!selected.matches_request(artifact));
        }
    }
    assert!(
        condition(
            "/event_type",
            JsonCondition::Equals(json!("session.created"))
        )
        .matches_request(&valid)
    );
}

#[test]
fn overlap_proofs_are_symmetric_and_only_use_a_shared_exact_discriminator() {
    let equals_a = condition("/event_type", JsonCondition::Equals(json!("a")));
    let equals_b = condition("/event_type", JsonCondition::Equals(json!("b")));
    let not_a = condition("/event_type", JsonCondition::NotEquals(json!("a")));
    let not_b = condition("/event_type", JsonCondition::NotEquals(json!("b")));
    let other_pointer = condition("/data/type", JsonCondition::Equals(json!("b")));
    for (left, right, expected) in [
        (None, None, true),
        (None, Some(&equals_a), true),
        (Some(&equals_a), Some(&equals_a), true),
        (Some(&equals_a), Some(&equals_b), false),
        (Some(&equals_a), Some(&not_a), false),
        (Some(&equals_a), Some(&not_b), true),
        (Some(&not_a), Some(&not_a), true),
        (Some(&not_a), Some(&not_b), true),
        (Some(&equals_a), Some(&other_pointer), true),
    ] {
        assert_eq!(overlaps(left, right), expected);
        assert_eq!(overlaps(right, left), expected);
    }
    let both = CaseCondition {
        request_body_json: BTreeMap::from([
            ("/event_type".into(), JsonCondition::Equals(json!("a"))),
            ("/data/enabled".into(), JsonCondition::Equals(json!(true))),
        ]),
    };
    assert!(!overlaps(Some(&both), Some(&equals_b)));
    assert!(overlaps(Some(&both), Some(&not_b)));
}
