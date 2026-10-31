use super::*;

fn generated_rule(kind: &str, pointer: &str) -> String {
    let time = match kind {
        "timestamp" => "          format: unix_seconds\n",
        "duration" => "          unit: seconds\n",
        _ => "",
    };
    format!(
        "response_rules:\n  json:\n    'GET /api/resource/token':\n      {kind}:\n        - pointer: {pointer}\n{time}          source_evidence: src/generator.rs:generate\n          source_example: '<source generated value>'\n          target_example: '<target generated value>'\n"
    )
}

#[test]
fn all_generated_rules_support_variable_and_nested_arrays() {
    for kind in ["timestamp", "duration", "uuid", "random"] {
        let (source, target) = match kind {
            "timestamp" => (json!(1700000000), json!(1700000060)),
            "duration" => (json!(120), json!(180)),
            "uuid" => (
                json!("11111111-1111-4111-8111-111111111111"),
                json!("22222222-2222-4222-8222-222222222222"),
            ),
            _ => (json!("source"), json!("target")),
        };
        for count in [0, 1, 3] {
            let expected = json!({"data": (0..count).map(|index| json!({
                "stable": index, "items": [{"value": source}, {"value": source}]
            })).collect::<Vec<_>>()});
            let actual = json!({"data": (0..count).map(|index| json!({
                "stable": index, "items": [{"value": target}, {"value": target}]
            })).collect::<Vec<_>>()});
            let (_temp, options) = write_raw_case(
                &generated_rule(kind, "/data/*/items/*/value"),
                &expected.to_string(),
                &actual.to_string(),
            );
            let report = assert_recorded_response(options).unwrap();
            assert!(report.passed, "{kind}: {report:?}");
            assert_eq!(report.applied_body_rule_ids.len(), usize::from(count > 0));
            assert!(report.unused_applicable_generated_rule_ids.is_empty());
        }
    }
}

#[test]
fn array_rules_keep_missing_types_lengths_order_and_other_fields_exact() {
    let expected = json!({"data": [{"value": "src1", "id": "a"}, {"value": "src2", "id": "b"}]});
    for (actual, pointer, kind) in [
        (
            json!({"data": [{"id": "a"}, {"value": "tgt2", "id": "b"}]}),
            "/data/0/value",
            ResponseDifferenceKind::MissingActual,
        ),
        (
            json!({"data": [{"value": 3, "id": "a"}, {"value": "tgt2", "id": "b"}]}),
            "/data/0/value",
            ResponseDifferenceKind::GeneratedFieldNotScalar,
        ),
        (
            json!({"data": [{"value": "tgt1", "id": "a"}, {"value": null, "id": "b"}]}),
            "/data/1/value",
            ResponseDifferenceKind::GeneratedFieldNotScalar,
        ),
        (
            json!({"data": [{"value": "tgt1", "id": "a"}]}),
            "/data",
            ResponseDifferenceKind::ArrayLengthMismatch,
        ),
        (
            json!({"data": [{"value": "tgt1", "id": "changed"}, {"value": "tgt2", "id": "b"}]}),
            "/data/0/id",
            ResponseDifferenceKind::ValueMismatch,
        ),
        (
            json!({"data": [{"value": "src2", "id": "b"}, {"value": "src1", "id": "a"}]}),
            "/data/0/id",
            ResponseDifferenceKind::ValueMismatch,
        ),
    ] {
        let (_temp, options) = write_raw_case(
            &generated_rule("random", "/data/*/value"),
            &expected.to_string(),
            &actual.to_string(),
        );
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert!(
            report
                .differences
                .iter()
                .any(|difference| difference.pointer == pointer && difference.kind == kind),
            "{report:?}"
        );
    }
}

#[test]
fn array_rules_do_not_relax_numeric_object_keys() {
    let (_temp, options) = write_raw_case(
        &generated_rule("uuid", "/data/*/value"),
        r#"{"data":{"0":{"value":"source"}}}"#,
        r#"{"data":{"0":{"value":"target"}}}"#,
    );
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert_eq!(report.differences[0].pointer, "/data/0/value");
    assert!(report.applied_body_rule_ids.is_empty());
}

#[test]
fn array_rules_support_root_scalars_and_keep_explicit_indexes() {
    for pointer in ["/*", "/0"] {
        let (_temp, options) = write_raw_case(
            &generated_rule("random", pointer),
            r#"["source","same"]"#,
            r#"["target","same"]"#,
        );
        assert!(assert_recorded_response(options).unwrap().passed);
    }
}

#[test]
fn time_array_rules_fail_on_one_invalid_element_or_missing_response_time() {
    for (kind, source, target, failure) in [
        (
            "timestamp",
            1700000000_i64,
            1700000066_i64,
            ResponseDifferenceKind::DurationDeltaMismatch,
        ),
        (
            "duration",
            120,
            186,
            ResponseDifferenceKind::DurationDeltaMismatch,
        ),
    ] {
        let valid_target = if kind == "timestamp" {
            1700000060_i64
        } else {
            180
        };
        let (_temp, options) = write_raw_case(
            &generated_rule(kind, "/data/*/value"),
            &json!({"data": [{"value": source}, {"value": source}]}).to_string(),
            &json!({"data": [{"value": valid_target}, {"value": target}]}).to_string(),
        );
        let report = assert_recorded_response(ResponseAssertionOptions {
            case_id: options.case_id.clone(),
            request: options.request.clone(),
            expected_response: options.expected_response.clone(),
            actual_response: options.actual_response.clone(),
            policy: options.policy.clone(),
        })
        .unwrap();
        assert!(!report.passed);
        assert_eq!(report.applied_body_rule_ids.len(), 1);
        assert!(
            report
                .differences
                .iter()
                .any(|difference| difference.pointer == "/data/1/value"
                    && difference.kind == failure)
        );
        let mut actual: serde_json::Value =
            serde_json::from_slice(&fs::read(&options.actual_response).unwrap()).unwrap();
        actual
            .as_object_mut()
            .unwrap()
            .remove("response_completed_at");
        fs::write(
            &options.actual_response,
            serde_json::to_vec(&actual).unwrap(),
        )
        .unwrap();
        let report = assert_recorded_response(options).unwrap();
        assert!(!report.passed);
        assert!(
            report
                .differences
                .iter()
                .all(|difference| difference.kind == ResponseDifferenceKind::TimeReferenceMissing)
        );
    }
}

#[test]
fn array_selection_is_shared_by_unordered_and_joined_string_rules() {
    for (kind, extra, expected, actual) in [
        (
            "unordered",
            "",
            json!([{"names": ["alice", "bob"]}, {"names": ["eve", "dan"]}]),
            json!([{"names": ["bob", "alice"]}, {"names": ["dan", "eve"]}]),
        ),
        (
            "unordered_joined_string",
            "          separator: ','\n",
            json!([{"names": "alice,bob"}, {"names": "eve,dan"}]),
            json!([{"names": "bob,alice"}, {"names": "dan,eve"}]),
        ),
    ] {
        let rules = format!(
            "response_rules:\n  json:\n    'GET /api/resource/token':\n      {kind}:\n        - pointer: /content/*/names\n{extra}          source_evidence: src/names.rs:set\n"
        );
        let (_temp, options) = write_case(&rules, expected, actual);
        let report = assert_recorded_response(options).unwrap();
        assert!(report.passed, "{report:?}");
    }
}
