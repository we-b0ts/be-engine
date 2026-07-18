use std::fs;

use serde_json::json;
use tempfile::tempdir;

use super::model::ResponseDifferenceKind;
use super::*;

fn write_case(
    response_rules: &str,
    expected_content: serde_json::Value,
    actual_content: serde_json::Value,
) -> (tempfile::TempDir, ResponseAssertionOptions) {
    let temp = tempdir().unwrap();
    let request = temp.path().join("request.json");
    let expected = temp.path().join("expected-response.json");
    let actual = temp.path().join("actual-response.json");
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &request,
        serde_json::to_vec(&json!({
            "method": "GET",
            "uri": "/api/resource/token"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &expected,
        serde_json::to_vec(&json!({
            "status": 200,
            "body": {
                "encoding": "utf8",
                "data": json!({"content": expected_content}).to_string(),
                "truncated": false
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &actual,
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "body": {
                "encoding": "utf8",
                "data": json!({"content": actual_content}).to_string(),
                "truncated": false
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &policy,
        format!("version: 2\nexpected_response: assertions_only\nrules: []\n{response_rules}"),
    )
    .unwrap();
    let options = ResponseAssertionOptions {
        case_id: "case-1".to_string(),
        request,
        expected_response: expected,
        actual_response: actual,
        policy,
    };
    (temp, options)
}

#[test]
fn dynamic_scalar_skips_only_its_literal_value() {
    let (_temp, options) = write_case(
        "response_rules:\n  dynamic:\n    \"GET /api/resource/token\":\n      - /content\n",
        json!("recorded"),
        json!("actual"),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.applied_dynamic_rule_ids.len(), 1);
    assert!(report.differences.is_empty());
}

#[test]
fn exact_mismatch_surfaces_a_dynamic_candidate() {
    let (_temp, options) = write_case("", json!("recorded"), json!("actual"));

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.dynamic_candidates, vec!["/content"]);
}

#[test]
fn dynamic_field_still_requires_the_same_scalar_type() {
    let (_temp, options) = write_case(
        "response_rules:\n  dynamic:\n    \"GET /api/resource/token\":\n      - /content\n",
        json!("recorded"),
        json!(42),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::DynamicFieldNotScalar
    );
}

#[test]
fn exact_array_reordering_surfaces_an_unordered_candidate() {
    let (_temp, options) = write_case("", json!(["a", "b", "a"]), json!(["a", "a", "b"]));

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.unordered_candidates, vec!["/content"]);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ArrayOrderMismatch
    );
}

#[test]
fn unordered_array_compares_nested_values_as_a_multiset() {
    let (_temp, options) = write_case(
        "response_rules:\n  unordered:\n    \"GET /api/resource/token\":\n      - /content\n",
        json!([{"id": 1}, "same", "same"]),
        json!(["same", {"id": 1}, "same"]),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.applied_unordered_rule_ids.len(), 1);
    assert!(report.unused_applicable_unordered_rule_ids.is_empty());
}

#[test]
fn unordered_array_preserves_duplicate_counts() {
    let (_temp, options) = write_case(
        "response_rules:\n  unordered:\n    \"GET /api/resource/token\":\n      - /content\n",
        json!(["same", "same"]),
        json!(["same", "other"]),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::UnorderedArrayContentMismatch
    );
    assert_eq!(report.unused_applicable_unordered_rule_ids.len(), 1);
}

#[test]
fn unordered_field_requires_arrays_on_both_sides() {
    let (_temp, options) = write_case(
        "response_rules:\n  unordered:\n    \"GET /api/resource/token\":\n      - /content\n",
        json!(["same"]),
        json!({"0": "same"}),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::UnorderedFieldNotArray
    );
}

#[test]
fn unordered_field_must_exist_in_both_responses() {
    let (_temp, options) = write_case(
        "response_rules:\n  unordered:\n    \"GET /api/resource/token\":\n      - /missing\n",
        json!(["same"]),
        json!(["same"]),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert!(report.differences.is_empty());
    assert_eq!(report.unused_applicable_unordered_rule_ids.len(), 1);
}
