use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::json;
use tempfile::tempdir;
use traffic_e2e::{
    ComparisonVerificationClassification, ComparisonVerificationOptions, MatchedSourceObservation,
    ResponseDifferenceKind, verify_comparison_recording,
};

#[test]
fn reuses_replay_response_rules_for_offline_comparison() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"token": "baseline"}),
        json!({"token": "candidate"}),
    );
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &policy,
        r#"version: 2
expected_response: assertions_only
rules: []
response_rules:
  dynamic:
    "GET /api/token":
      - pointer: /token
        mechanisms: [uuid]
        source_evidence: src/token.rs:issue_token
        source_example: <redacted source UUID>
        target_example: <redacted target UUID>
"#,
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy,
        report: report_path.clone(),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert!(report.representative_difference.is_none());
    assert_eq!(report.counts.passed, 1);
    assert_eq!(report.counts.apis_total, 1);
    assert_eq!(report.counts.apis_passed, 1);
    assert!(report.apis["GET /api/token"].passed);
    assert_eq!(report.cases[0].api, "GET /api/token");
    assert_eq!(
        report.cases[0]
            .response
            .as_ref()
            .unwrap()
            .applied_dynamic_rule_ids
            .len(),
        1
    );
    assert!(report_path.is_file());
}

#[test]
fn applies_explicit_comparison_counter_rules_by_representation_class() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({
            "followers_count": 100,
            "followers_count_str": "100",
            "empty_count_str": ""
        }),
        json!({
            "followers_count": 101,
            "followers_count_str": "101",
            "empty_count_str": ""
        }),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 2
expected_response: assertions_only
rules: []
response_rules:
  comparison:
    counter:
      "GET /api/token":
        - pointer: /empty_count_str
          source_evidence: src/user.rs:load live counters
          source_example: <empty>
          target_example: <nonempty observation>
        - pointer: /followers_count
          source_evidence: src/user.rs:load live counters
          source_example: "100"
          target_example: "101"
        - pointer: /followers_count_str
          source_evidence: src/user.rs:load live counters
          source_example: "100"
          target_example: "101"
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(
        report.cases[0]
            .response
            .as_ref()
            .unwrap()
            .applied_counter_rule_ids
            .len(),
        3
    );
}

#[test]
fn comparison_counter_rules_preserve_type_presence_and_empty_string() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({
            "followers_count": 100,
            "followers_count_str": "",
            "friends_count": 3
        }),
        json!({
            "followers_count": "101",
            "followers_count_str": "0"
        }),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 2
expected_response: assertions_only
rules: []
response_rules:
  comparison:
    counter:
      "GET /api/token":
        - pointer: /followers_count
          source_evidence: src/user.rs:load live counters
          source_example: "100"
          target_example: "101"
        - pointer: /followers_count_str
          source_evidence: src/user.rs:load live counters
          source_example: <empty>
          target_example: "0"
        - pointer: /friends_count
          source_evidence: src/user.rs:load live counters
          source_example: "3"
          target_example: <missing>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    let response = report.cases[0].response.as_ref().unwrap();
    assert_eq!(response.differences.len(), 3);
    assert_eq!(
        response
            .differences
            .iter()
            .map(|difference| difference.pointer.as_str())
            .collect::<Vec<_>>(),
        vec!["/followers_count", "/followers_count_str", "/friends_count"]
    );
    assert!(response.applied_counter_rule_ids.is_empty());
}

#[test]
fn a_rule_used_by_the_candidate_is_not_stale_when_the_source_recheck_is_stable() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"token": "baseline"}),
        json!({"token": "candidate"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"token": "baseline"}),
    );
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &policy,
        r#"version: 2
expected_response: assertions_only
rules: []
response_rules:
  dynamic:
    "GET /api/token":
      - pointer: /token
        mechanisms: [uuid]
        source_evidence: src/token.rs:issue_token
        source_example: <redacted source UUID>
        target_example: <redacted target UUID>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(report.counts.policy_mismatch, 0);
    assert!(report.cases[0].policy_mismatch_rule_ids.is_empty());
}

#[test]
fn compares_a_legacy_gzip_response_with_an_uncompressed_response() {
    let temp = tempdir().unwrap();
    let body = json!({"token": "same"});
    let run = create_run(temp.path(), body.clone(), body.clone());
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&serde_json::to_vec(&body).unwrap())
        .unwrap();
    let compressed = encoder.finish().unwrap();
    fs::write(
        case.join("expected-response.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "headers": {
                "content-encoding": ["gzip"],
                "content-type": ["application/json"]
            },
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(compressed),
                "truncated": false
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert_eq!(report.counts.passed, 1);
}

#[test]
fn writes_a_failed_report_for_an_unexempted_difference() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"token": "baseline"}),
        json!({"token": "candidate"}),
    );
    let policy = temp.path().join("replay.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let report_path = run.join("comparison-report.json");

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run,
        policy,
        report: report_path.clone(),
    })
    .unwrap();

    assert!(report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.failed, 1);
    assert_eq!(
        report.cases[0]
            .response
            .as_ref()
            .unwrap()
            .dynamic_candidates,
        ["/token"]
    );
    let representative = report.representative_difference.as_ref().unwrap();
    assert_eq!(representative.api, "GET /api/token");
    assert_eq!(
        representative.case_id,
        "00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(representative.pointer, "/token");
    assert_eq!(
        representative.difference_kind,
        ResponseDifferenceKind::ValueMismatch
    );
    assert_eq!(representative.source_before, json!("baseline"));
    assert_eq!(representative.candidate, json!("candidate"));
    assert_eq!(representative.source_after, json!("not_recorded"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(report_path).unwrap()).unwrap()["passed"],
        false
    );
}

#[test]
fn classifies_an_overlapping_baseline_change_as_source_change() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"value": "before"}),
        json!({"value": "candidate"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"value": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.inconclusive, 1);
    assert_eq!(report.counts.source_changed_cases, 1);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceChange
    );
    assert_eq!(report.cases[0].source_change_pointers, ["/value"]);
    assert!(report.cases[0].candidate_only_pointers.is_empty());
    assert!(!report.cases[0].baseline_recheck.as_ref().unwrap().passed);
    let representative = report.representative_difference.as_ref().unwrap();
    assert_eq!(representative.pointer, "/value");
    assert_eq!(representative.source_before, json!("before"));
    assert_eq!(representative.candidate, json!("candidate"));
    assert_eq!(representative.source_after, json!("after"));
}

#[test]
fn source_after_is_not_an_alternate_oracle_by_default() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"left": "before", "right": "before"}),
        json!({"left": "after", "right": "after"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"left": "after", "right": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceChange
    );
    assert_eq!(report.cases[0].matched_source, None);
    assert!(report.cases[0].response_after.is_none());
}

#[test]
fn before_or_after_accepts_a_complete_source_after_match() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"left": "before", "right": "before"}),
        json!({"left": "after", "right": "after"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"left": "after", "right": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\nresponse_rules:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.complete);
    assert!(report.passed);
    assert_eq!(report.counts.passed, 1);
    assert_eq!(
        report.cases[0].matched_source,
        Some(MatchedSourceObservation::After)
    );
    assert!(
        report.cases[0]
            .response_after
            .as_ref()
            .unwrap()
            .differences
            .is_empty()
    );
}

#[test]
fn before_or_after_does_not_mix_fields_from_source_observations() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"left": "before", "right": "before"}),
        json!({"left": "before", "right": "after"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"left": "after", "right": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\nresponse_rules:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceChange
    );
    assert_eq!(report.cases[0].matched_source, None);
    assert_eq!(
        report.cases[0]
            .response_after
            .as_ref()
            .unwrap()
            .differences
            .len(),
        1
    );
}

#[test]
fn before_or_after_requires_a_source_after_artifact() {
    let temp = tempdir().unwrap();
    let body = json!({"value": "stable"});
    let run = create_run(temp.path(), body.clone(), body);
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\nresponse_rules:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.unevaluable, 1);
    assert!(
        report.cases[0]
            .error
            .as_deref()
            .unwrap()
            .contains("requires expected-response-after.json")
    );
}

#[test]
fn unrelated_source_change_does_not_hide_a_candidate_difference() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"source_owned": "before", "candidate_owned": "expected"}),
        json!({"source_owned": "before", "candidate_owned": "wrong"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"source_owned": "after", "candidate_owned": "expected"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::CandidateDifference
    );
    assert_eq!(report.cases[0].source_change_pointers, ["/source_owned"]);
    assert_eq!(
        report.cases[0].candidate_only_pointers,
        ["/candidate_owned"]
    );
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.counts.source_changed_cases, 1);
}

#[test]
fn source_change_is_diagnostic_when_candidate_matches_source_before() {
    let temp = tempdir().unwrap();
    let body = json!({"value": "before"});
    let run = create_run(temp.path(), body.clone(), body);
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    write_response(
        &case.join("expected-response-after.json"),
        json!({"value": "after"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::Passed
    );
    assert_eq!(report.cases[0].source_change_pointers, ["/value"]);
    assert_eq!(report.counts.source_changed_cases, 1);
}

#[test]
fn classifies_a_rule_unobserved_by_the_entire_api_as_policy_mismatch() {
    let temp = tempdir().unwrap();
    let body = json!({"value": "stable"});
    let run = create_run(temp.path(), body.clone(), body);
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 2
expected_response: assertions_only
rules: []
response_rules:
  dynamic:
    "GET /api/token":
      - pointer: /missing
        mechanisms: [uuid]
        source_evidence: src/token.rs:issue_token
        source_example: <redacted source UUID>
        target_example: <redacted target UUID>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::Passed
    );
    assert_eq!(report.counts.policy_mismatch, 1);
    assert!(report.cases[0].policy_mismatch_rule_ids.is_empty());
    assert_eq!(
        report.apis["GET /api/token"].policy_mismatch_rule_ids.len(),
        1
    );
    let representative = report.representative_policy_mismatch.as_ref().unwrap();
    assert_eq!(representative.api, "GET /api/token");
    assert!(representative.case_id.is_none());
    assert!(representative.rule_id.contains("/missing"));
}

#[test]
fn preserves_policy_mismatch_diagnostics_with_a_candidate_difference() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"value": "expected"}),
        json!({"value": "wrong"}),
    );
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        r#"version: 2
expected_response: assertions_only
rules: []
response_rules:
  dynamic:
    "GET /api/token":
      - pointer: /missing
        mechanisms: [uuid]
        source_evidence: src/token.rs:issue_token
        source_example: <redacted source UUID>
        target_example: <redacted target UUID>
"#,
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::CandidateDifference
    );
    assert_eq!(report.counts.failed, 1);
    assert_eq!(report.counts.policy_mismatch, 1);
    assert_eq!(report.apis["GET /api/token"].counts.policy_mismatch, 1);
    assert!(report.cases[0].policy_mismatch_rule_ids.is_empty());
    assert_eq!(
        report.apis["GET /api/token"].policy_mismatch_rule_ids.len(),
        1
    );
}

#[test]
fn marks_a_response_content_decoding_failure_as_unevaluable() {
    let temp = tempdir().unwrap();
    let run = create_run(
        temp.path(),
        json!({"value": "baseline"}),
        json!({"value": "candidate"}),
    );
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    fs::write(
        case.join("expected-response.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(b"not gzip"),
                "truncated": false,
                "decoded": false,
                "content_encoding": "gzip",
                "decode_error": "failed to decode gzip body"
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = temp.path().join("verification.yaml");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let report = verify_comparison_recording(ComparisonVerificationOptions {
        case_source: run.clone(),
        policy,
        report: run.join("comparison-report.json"),
    })
    .unwrap();

    assert!(!report.complete);
    assert!(!report.passed);
    assert_eq!(report.counts.unevaluable, 1);
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::Unevaluable
    );
    assert!(
        report.cases[0]
            .error
            .as_deref()
            .unwrap()
            .contains("content decoding failed: failed to decode gzip body")
    );
}

fn create_run(root: &Path, expected: serde_json::Value, response: serde_json::Value) -> PathBuf {
    let run = root.join("comparison-recordings/20260722160000");
    let case = run.join("record-api/api-token/00000000-0000-4000-8000-000000000001");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        run.join("comparison-recording-run.json"),
        serde_json::to_vec(&json!({
            "status": "completed",
            "ready": true,
            "finished_at": "2026-07-22T16:00:01Z",
            "counts": {"published": 1}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        case.join("case-kind.json"),
        r#"{"version":1,"kind":"comparison_recording"}"#,
    )
    .unwrap();
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({
            "method": "GET",
            "uri": "/api/token",
            "api_pattern": "/api/token"
        }))
        .unwrap(),
    )
    .unwrap();
    write_response(&case.join("expected-response.json"), expected);
    write_response(&case.join("response.json"), response);
    run
}

fn write_response(path: &Path, body: serde_json::Value) {
    fs::write(
        path,
        serde_json::to_vec(&json!({
            "version": 1,
            "status": 200,
            "body": {
                "encoding": "base64",
                "data": STANDARD.encode(serde_json::to_vec(&body).unwrap()),
                "truncated": false
            },
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
}
