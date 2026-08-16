use std::fs;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use motan_protocol::{FrameBuilder, META_PROCESS_TIME, Metadata};
use serde_json::json;
use tempfile::tempdir;

use super::model::ResponseDifferenceKind;
use super::*;

fn write_case(
    response_rules: &str,
    expected_content: serde_json::Value,
    actual_content: serde_json::Value,
) -> (tempfile::TempDir, ResponseAssertionOptions) {
    write_raw_case(
        response_rules,
        &json!({"content": expected_content}).to_string(),
        &json!({"content": actual_content}).to_string(),
    )
}

fn write_raw_case(
    response_rules: &str,
    expected_body: &str,
    actual_body: &str,
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
                "data": expected_body,
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
                "data": actual_body,
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

fn write_motan2_case(
    expected_process_time: Option<&str>,
    actual_process_time: Option<&str>,
    expected_stable_metadata: &str,
    actual_stable_metadata: &str,
    expected_body: &[u8],
    actual_body: &[u8],
) -> (tempfile::TempDir, ResponseAssertionOptions) {
    fn response(process_time: Option<&str>, stable_metadata: &str, body: &[u8]) -> Vec<u8> {
        let mut metadata = Metadata::new();
        metadata.insert("stable", stable_metadata);
        if let Some(process_time) = process_time {
            metadata.insert(META_PROCESS_TIME, process_time);
        }
        FrameBuilder::response(42)
            .metadata(metadata)
            .body(body.to_vec())
            .encode()
            .unwrap()
            .to_vec()
    }

    let temp = tempdir().unwrap();
    let request = temp.path().join("request.json");
    let expected = temp.path().join("expected-response.json");
    let actual = temp.path().join("actual-response.json");
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &request,
        serde_json::to_vec(&json!({
            "method": "MOTAN",
            "uri": "/rpc/example",
            "protocol_version": "motan2"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &expected,
        serde_json::to_vec(&json!({
            "status": "normal",
            "frame": {
                "encoding": "base64",
                "data": STANDARD.encode(response(
                    expected_process_time,
                    expected_stable_metadata,
                    expected_body
                )),
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
                "encoding": "base64",
                "data": STANDARD.encode(response(
                    actual_process_time,
                    actual_stable_metadata,
                    actual_body
                )),
                "truncated": false
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let options = ResponseAssertionOptions {
        case_id: "motan-case-1".to_string(),
        request,
        expected_response: expected,
        actual_response: actual,
        policy,
    };
    (temp, options)
}

#[test]
fn empty_bodies_compare_as_exact_bytes() {
    let (_temp, options) = write_raw_case("", "", "");

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_mode, ResponseBodyMode::ExactBytes);
    assert!(report.differences.is_empty());
}

#[test]
fn empty_body_does_not_match_nonempty_body() {
    let (_temp, options) = write_raw_case("", "", "{}");

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.body_mode, ResponseBodyMode::ExactBytes);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ExactBodyMismatch
    );
}

#[test]
fn motan2_process_time_does_not_affect_response_assertion() {
    let (_temp, options) = write_motan2_case(
        Some("3"),
        Some("1"),
        "value",
        "value",
        b"business",
        b"business",
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert_eq!(report.body_mode, ResponseBodyMode::ExactBytes);
    assert!(report.differences.is_empty());
}

#[test]
fn motan2_process_time_presence_does_not_affect_response_assertion() {
    let (_temp, options) =
        write_motan2_case(Some("3"), None, "value", "value", b"business", b"business");

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert!(report.differences.is_empty());
}

#[test]
fn motan2_business_body_remains_exact_after_process_time_normalization() {
    let (_temp, options) = write_motan2_case(
        Some("3"),
        Some("1"),
        "value",
        "value",
        b"M_pt\n3",
        b"M_pt\n1",
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.body_mode, ResponseBodyMode::ExactBytes);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ExactBodyMismatch
    );
}

#[test]
fn motan2_other_metadata_remains_exact_after_process_time_normalization() {
    let (_temp, options) = write_motan2_case(
        Some("3"),
        Some("1"),
        "source",
        "target",
        b"business",
        b"business",
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::ExactBodyMismatch
    );
}

#[test]
fn dynamic_scalar_skips_only_its_literal_value() {
    let (_temp, options) = write_case(
        "response_rules:\n  dynamic:\n    \"GET /api/resource/token\":\n      - pointer: /content\n        mechanisms: [uuid]\n        source_evidence: src/token.rs:issue_token\n        source_example: <redacted source UUID>\n        target_example: <redacted target UUID>\n",
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
fn comparison_counter_rules_do_not_relax_standard_replay() {
    let (_temp, options) = write_case(
        "response_rules:\n  comparison:\n    counter:\n      \"GET /api/resource/token\":\n        - pointer: /content\n          source_evidence: src/counter.rs:load current count\n          source_example: '100'\n          target_example: '101'\n",
        json!(100),
        json!(101),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert!(report.applied_counter_rule_ids.is_empty());
    assert_eq!(report.dynamic_candidates, vec!["/content"]);
}

#[test]
fn dynamic_field_still_requires_the_same_scalar_type() {
    let (_temp, options) = write_case(
        "response_rules:\n  dynamic:\n    \"GET /api/resource/token\":\n      - pointer: /content\n        mechanisms: [uuid]\n        source_evidence: src/token.rs:issue_token\n        source_example: <redacted source UUID>\n        target_example: <redacted target UUID>\n",
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
fn an_unordered_rule_absent_from_both_response_shapes_is_irrelevant() {
    let (_temp, options) = write_case(
        "response_rules:\n  unordered:\n    \"GET /api/resource/token\":\n      - /missing\n",
        json!(["same"]),
        json!(["same"]),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert!(report.differences.is_empty());
    assert!(report.unused_applicable_unordered_rule_ids.is_empty());
}

#[test]
fn a_dynamic_rule_absent_from_both_response_shapes_is_irrelevant() {
    let (_temp, options) = write_case(
        "response_rules:\n  dynamic:\n    \"GET /api/resource/token\":\n      - pointer: /missing\n        mechanisms: [uuid]\n        source_evidence: src/token.rs:issue_token\n        source_example: <redacted source UUID>\n        target_example: <redacted target UUID>\n",
        json!("same"),
        json!("same"),
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(report.passed);
    assert!(report.differences.is_empty());
    assert!(report.unused_applicable_dynamic_rule_ids.is_empty());
}

#[test]
fn a_rule_present_on_only_one_side_remains_an_exact_difference() {
    let (_temp, options) = write_raw_case(
        "response_rules:\n  dynamic:\n    \"GET /api/resource/token\":\n      - pointer: /content\n        mechanisms: [uuid]\n        source_evidence: src/token.rs:issue_token\n        source_example: <redacted source UUID>\n        target_example: <redacted target UUID>\n",
        r#"{"content":"recorded"}"#,
        "{}",
    );

    let report = assert_recorded_response(options).unwrap();

    assert!(!report.passed);
    assert_eq!(report.differences.len(), 1);
    assert_eq!(
        report.differences[0].kind,
        ResponseDifferenceKind::MissingActual
    );
    assert!(report.unused_applicable_dynamic_rule_ids.is_empty());
}
