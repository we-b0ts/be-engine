use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use tempfile::tempdir;
use traffic_e2e::{
    ComparisonVerificationClassification, ComparisonVerificationOptions,
    verify_comparison_recording,
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
      - /token
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
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(report_path).unwrap()).unwrap()["passed"],
        false
    );
}

#[test]
fn classifies_a_changed_baseline_recheck_as_source_drift() {
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
    assert_eq!(
        report.cases[0].classification,
        ComparisonVerificationClassification::SourceDrift
    );
    assert!(!report.cases[0].baseline_recheck.as_ref().unwrap().passed);
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
