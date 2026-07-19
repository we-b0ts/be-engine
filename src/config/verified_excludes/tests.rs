use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::AppConfig;

const CONFIG: &str = r#"[http_gateway]
enabled = true

[http_gateway.verified_excludes]
# BEGIN AI-MANAGED VERIFIED API EXCLUDES
apis = [
]
# END AI-MANAGED VERIFIED API EXCLUDES

[[http_gateway.rules]]
name = "record-api"
methods = ["GET"]
path_prefixes = ["/api"]
case_path_patterns = ["/api/users/*"]

[recording]
access_policy = "unrestricted"
"#;

#[test]
fn plans_and_applies_exclude_after_threshold_successes() {
    let fixture = fixture(&[true, true, true], true, false);
    let plan = plan_verified_api_exclude(fixture.feedback()).unwrap();

    assert!(plan.report().eligible);
    assert!(plan.report().changed);
    assert_eq!(plan.report().verification.consecutive_successful_runs, 3);
    assert_eq!(plan.report().verification.consecutive_successful_cases, 3);
    assert_eq!(plan.report().added.len(), 1);

    let report = plan.apply().unwrap();
    assert!(report.applied);
    let config = AppConfig::load(&fixture.config_path).unwrap();
    assert_eq!(config.http_gateway.verified_excludes.apis.len(), 1);

    let repeated = plan_verified_api_exclude(fixture.feedback()).unwrap();
    assert!(repeated.report().eligible);
    assert!(!repeated.report().changed);
    assert!(repeated.report().added.is_empty());
}

#[test]
fn accepts_only_a_trailing_verified_exclude_catch_all() {
    assert!(validate_path_pattern("/api/users").is_ok());
    assert!(validate_path_pattern("/api/users/*").is_ok());
    assert!(validate_path_pattern("/api/namespaces/**").is_ok());

    let embedded = validate_path_pattern("/api/user-*").unwrap_err();
    assert!(embedded.to_string().contains("whole path segment"));

    let non_trailing = validate_path_pattern("/api/**/pods").unwrap_err();
    assert!(non_trailing.to_string().contains("final path segment"));
}

#[test]
fn ensure_applies_a_trailing_catch_all_exclude() {
    let fixture = fixture(&[true, true, true], true, false);

    let report = ensure_verified_api_exclude(fixture.feedback_for("/api/users/**")).unwrap();

    assert_eq!(report.status, VerifiedApiExcludeEnsureStatus::Applied);
    assert_eq!(report.plan.matching_case_ids.len(), 3);
    assert_eq!(report.plan.path_pattern, "/api/users/**");
    let config = AppConfig::load(&fixture.config_path).unwrap();
    assert_eq!(
        config.http_gateway.verified_excludes.apis[0].path_pattern,
        "/api/users/**"
    );
}

#[test]
fn failed_latest_assertion_resets_consecutive_success_count() {
    let fixture = fixture(&[true, true, false], true, false);
    let plan = plan_verified_api_exclude(fixture.feedback()).unwrap();

    assert!(!plan.report().eligible);
    assert_eq!(
        plan.report().blockers,
        vec!["current_assertions_not_successful"]
    );
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("not eligible")
    );
    assert_eq!(fs::read_to_string(&fixture.config_path).unwrap(), CONFIG);
}

#[test]
fn dirty_or_incomplete_aggregate_cannot_make_an_exclude_eligible() {
    let fixture = fixture(&[true, true, true], false, true);
    let plan = plan_verified_api_exclude(fixture.feedback()).unwrap();

    assert!(!plan.report().eligible);
    assert_eq!(
        plan.report().blockers,
        vec!["aggregate_incomplete", "aggregate_dirty"]
    );
}

#[test]
fn assertion_report_must_cover_the_exact_matching_case_set() {
    let fixture = fixture(&[true, true, true], true, false);
    let mut assertion: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.assertion_path).unwrap()).unwrap();
    assertion["cases"].as_array_mut().unwrap().pop();
    fs::write(
        &fixture.assertion_path,
        serde_json::to_vec_pretty(&assertion).unwrap(),
    )
    .unwrap();

    let error = plan_verified_api_exclude(fixture.feedback()).unwrap_err();
    assert!(error.to_string().contains("every published matching case"));
}

#[test]
fn aggregate_report_must_prove_assertion_only_replay_policy() {
    let fixture = fixture(&[true, true, true], true, false);
    let mut aggregate: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.aggregate_path).unwrap()).unwrap();
    aggregate["reports"][0]
        .as_object_mut()
        .unwrap()
        .remove("replay_policy");
    fs::write(
        &fixture.aggregate_path,
        serde_json::to_vec_pretty(&aggregate).unwrap(),
    )
    .unwrap();

    let error = plan_verified_api_exclude(fixture.feedback()).unwrap_err();
    assert!(error.to_string().contains("no replay policy evidence"));
}

#[test]
fn ensure_applies_eligible_exclude_and_verifies_convergence() {
    let fixture = fixture(&[true, true, true], true, false);

    let report = ensure_verified_api_exclude(fixture.feedback()).unwrap();

    assert_eq!(report.status, VerifiedApiExcludeEnsureStatus::Applied);
    assert!(report.plan.changed);
    assert!(report.apply.as_ref().unwrap().applied);
    let verification = report.verification.as_ref().unwrap();
    assert!(verification.eligible);
    assert!(!verification.changed);
    let repeated = ensure_verified_api_exclude(fixture.feedback()).unwrap();
    assert_eq!(
        repeated.status,
        VerifiedApiExcludeEnsureStatus::AlreadyPresent
    );
    assert!(repeated.apply.is_none());
}

#[test]
fn ensure_records_below_threshold_without_changing_config() {
    let fixture = fixture(&[true, true], true, false);

    let report = ensure_verified_api_exclude(fixture.feedback_with_verification(
        "/api/users/*",
        VerifiedApiVerification {
            consecutive_successful_runs: 1,
            consecutive_successful_cases: 2,
            required_consecutive_successful_runs: 3,
            required_successful_cases: 3,
        },
    ))
    .unwrap();

    assert_eq!(
        report.status,
        VerifiedApiExcludeEnsureStatus::BelowThreshold
    );
    assert_eq!(report.plan.verification.consecutive_successful_cases, 2);
    assert_eq!(
        report.plan.blockers,
        vec![
            "consecutive_successful_runs_below_threshold",
            "successful_cases_below_threshold"
        ]
    );
    assert!(report.apply.is_none());
    assert_eq!(fs::read_to_string(&fixture.config_path).unwrap(), CONFIG);
}

#[test]
fn ensure_rejects_dirty_or_incomplete_evidence_instead_of_skipping() {
    let fixture = fixture(&[true, true, true], false, true);

    let error = ensure_verified_api_exclude(fixture.feedback()).unwrap_err();

    assert!(error.to_string().contains("evidence is blocked"));
    assert!(error.to_string().contains("aggregate_incomplete"));
    assert!(error.to_string().contains("aggregate_dirty"));
    assert_eq!(fs::read_to_string(&fixture.config_path).unwrap(), CONFIG);
}

#[test]
fn apply_rejects_assertion_evidence_changed_after_plan() {
    let fixture = fixture(&[true, true, true], true, false);
    let plan = plan_verified_api_exclude(fixture.feedback()).unwrap();
    let mut assertions: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.assertion_path).unwrap()).unwrap();
    assertions["cases"][0]["passed"] = json!(false);
    fs::write(
        &fixture.assertion_path,
        serde_json::to_vec_pretty(&assertions).unwrap(),
    )
    .unwrap();

    let error = plan.apply().unwrap_err();

    assert!(error.to_string().contains("assertion report changed"));
    assert_eq!(fs::read_to_string(&fixture.config_path).unwrap(), CONFIG);
}

struct Fixture {
    _temp: TempDir,
    config_path: PathBuf,
    aggregate_path: PathBuf,
    assertion_path: PathBuf,
}

impl Fixture {
    fn feedback(&self) -> VerifiedApiExcludeFeedback {
        self.feedback_for("/api/users/*")
    }

    fn feedback_for(&self, path_pattern: &str) -> VerifiedApiExcludeFeedback {
        self.feedback_with_verification(
            path_pattern,
            VerifiedApiVerification {
                consecutive_successful_runs: 3,
                consecutive_successful_cases: 3,
                required_consecutive_successful_runs: 3,
                required_successful_cases: 3,
            },
        )
    }

    fn feedback_with_verification(
        &self,
        path_pattern: &str,
        verification: VerifiedApiVerification,
    ) -> VerifiedApiExcludeFeedback {
        VerifiedApiExcludeFeedback {
            config_path: self.config_path.clone(),
            rule_name: "record-api".to_string(),
            method: "GET".to_string(),
            path_pattern: path_pattern.to_string(),
            aggregate_report: self.aggregate_path.clone(),
            assertion_report: self.assertion_path.clone(),
            verification,
        }
    }
}

fn fixture(assertions: &[bool], complete: bool, dirty: bool) -> Fixture {
    let temp = TempDir::new().unwrap();
    let config_path = temp.path().join("recorder.toml");
    fs::write(&config_path, CONFIG).unwrap();
    let case_source = temp.path().join("recordings").join("api-users-wildcard");
    fs::create_dir_all(&case_source).unwrap();
    let mut case_ids = Vec::new();
    for (index, _) in assertions.iter().enumerate() {
        let case_id = format!("case-{}", index + 1);
        write_case(&case_source, &case_id, index);
        case_ids.push(case_id);
    }
    let case_source = case_source.canonicalize().unwrap();
    let aggregate_path = temp.path().join("aggregate.json");
    fs::write(
        &aggregate_path,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "case_source": case_source,
            "selected_case_ids": case_ids,
            "complete": complete,
            "dirty": dirty,
            "reports": [{
                "path": "/recordings/replay-report.json",
                "complete": true,
                "dirty": false,
                "replay_policy": {
                    "path": "/target/config/replay.yaml",
                    "fingerprint": "fnv1a64:0123456789abcdef",
                    "expected_response": "assertions_only",
                    "unused_applicable_rule_ids": []
                }
            }],
            "cases": case_ids.iter().map(|case_id| json!({
                "case_id": case_id,
                "status": "ended",
                "report": "/recordings/replay-report.json"
            })).collect::<Vec<_>>()
        }))
        .unwrap(),
    )
    .unwrap();
    let assertion_path = temp.path().join("assertions.json");
    fs::write(
        &assertion_path,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "case_source": case_source,
            "expected_response": "assertions_only",
            "cases": case_ids.iter().zip(assertions).map(|(case_id, passed)| json!({
                "case_id": case_id,
                "passed": passed
            })).collect::<Vec<_>>()
        }))
        .unwrap(),
    )
    .unwrap();
    Fixture {
        _temp: temp,
        config_path,
        aggregate_path,
        assertion_path,
    }
}

fn write_case(case_source: &Path, case_id: &str, index: usize) {
    let directory = case_source.join(case_id);
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("request.json"),
        serde_json::to_vec_pretty(&json!({
            "timestamp": format!("2026-07-15T04:30:0{index}Z"),
            "method": "GET",
            "uri": format!("/api/users/user-{index}"),
            "matched_rule": "record-api"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(directory.join("expected-response.json"), b"{}\n").unwrap();
}
