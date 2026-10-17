use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;
use crate::config::SourceTrafficPolicyConfig;

const REVISION: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const EVIDENCE: &str = "src/config/refresh.rs:42 process-level scheduled refresh";

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    replay_report: PathBuf,
}

impl Fixture {
    fn new(report: Value) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("source-traffic-policy.yaml");
        let replay_report = temp.path().join("replay-report.json");
        fs::write(
            &config,
            SourceTrafficPolicyConfig::empty().render().unwrap(),
        )
        .unwrap();
        fs::write(&replay_report, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        Self {
            _temp: temp,
            config,
            replay_report,
        }
    }

    fn feedback(&self) -> BackgroundDependencyFeedback {
        BackgroundDependencyFeedback {
            rules_path: self.config.clone(),
            replay_report_path: self.replay_report.clone(),
            name: "config-refresh".to_string(),
            authority: "CONFIG.API.demo.test".to_string(),
            method: "get".to_string(),
            path_prefix: "/1/config/service".to_string(),
            source_revision: REVISION.to_string(),
            source_evidence: EVIDENCE.to_string(),
        }
    }
}

fn evidence(case_id: &str, host: &str, port: u16, method: &str, uri: &str) -> Value {
    json!({
        "case_id": case_id,
        "target": {
            "host": host,
            "port": port,
        },
        "method": method,
        "uri": uri,
    })
}

fn report_with_unused() -> Value {
    json!({
        "finalized": true,
        "unused_case_http_exchanges": [
            evidence(
                "case-b",
                "config.api.demo.test",
                80,
                "GET",
                "/1/config/service?action=lookup&group=large"
            ),
            evidence(
                "case-a",
                "config.api.demo.test",
                80,
                "GET",
                "/1/config/service?action=lookup&group=small"
            ),
        ],
        "unmatched_http_requests": [],
        "unsupported_http_exchanges": [],
    })
}

#[test]
fn retries_policy_application_after_report_reclassification() {
    let fixture = Fixture::new(report_with_unused());
    plan_background_dependency(fixture.feedback())
        .unwrap()
        .apply()
        .unwrap();
    crate::replay::reclassify_background_dependencies(
        &fixture.config,
        &fixture.replay_report,
        &Default::default(),
    )
    .unwrap();
    let classified = fs::read(&fixture.replay_report).unwrap();
    let rules = fs::read(&fixture.config).unwrap();

    let retry = plan_background_dependency(fixture.feedback()).unwrap();
    assert!(retry.report().reused_existing);
    assert!(!retry.report().changed);
    assert_eq!(retry.report().matched_unused_exchanges, 2);
    assert_eq!(retry.report().matched_case_ids, ["case-a", "case-b"]);
    assert!(retry.apply().unwrap().applied);
    assert_eq!(fs::read(&fixture.config).unwrap(), rules);
    assert_eq!(fs::read(&fixture.replay_report).unwrap(), classified);

    let mut report: Value = serde_json::from_slice(&classified).unwrap();
    report["http_request_header_mismatches"] = json!([evidence(
        "case-a",
        "config.api.demo.test",
        80,
        "GET",
        "/1/config/service"
    )]);
    fs::write(&fixture.replay_report, report.to_string()).unwrap();
    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("request-header mismatch")
    );
}

#[test]
fn ordinary_global_exchanges_cannot_replace_unused_case_evidence() {
    let mut report = report_with_unused();
    report["unused_global_http_exchanges"] = report["unused_case_http_exchanges"].take();
    report["unused_case_http_exchanges"] = json!([]);
    let fixture = Fixture::new(report);
    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("matches no unused case")
    );
}

#[test]
fn header_mismatch_cannot_be_hidden_by_a_background_rule() {
    let mut report = report_with_unused();
    report["http_request_header_mismatches"] = json!([evidence(
        "case-a",
        "config.api.demo.test",
        80,
        "GET",
        "/1/config/service"
    )]);
    let fixture = Fixture::new(report);
    let error = plan_background_dependency(fixture.feedback())
        .err()
        .unwrap();
    assert!(error.to_string().contains("request-header mismatch"));
}

#[test]
fn plan_and_apply_add_a_valid_idempotent_managed_rule() {
    let fixture = Fixture::new(report_with_unused());

    let plan = plan_background_dependency(fixture.feedback()).unwrap();
    assert!(plan.report().changed);
    assert!(!plan.report().reused_existing);
    assert_eq!(plan.report().effective_name, "config-refresh");
    assert!(!plan.report().applied);
    assert_eq!(plan.report().authority, "config.api.demo.test");
    assert_eq!(plan.report().method, "GET");
    assert_eq!(plan.report().matched_unused_exchanges, 2);
    assert_eq!(plan.report().matched_case_ids, ["case-a", "case-b"]);
    let applied = plan.apply().unwrap();
    assert!(applied.applied);

    let raw = fs::read_to_string(&fixture.config).unwrap();
    assert!(raw.contains("format: traffic-policy/v1"));
    assert!(raw.contains("kind: process_owned"));
    assert!(raw.contains("protocol: http"));
    assert!(!raw.contains("response_role"));
    assert!(raw.contains("source_revision:"));
    assert!(raw.contains(EVIDENCE));
    let config = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
    assert_eq!(config.process_owned_dependencies.len(), 1);

    let repeated = plan_background_dependency(fixture.feedback()).unwrap();
    assert!(!repeated.report().changed);
    assert!(repeated.report().reused_existing);
    assert_eq!(repeated.report().effective_name, "config-refresh");
    assert!(repeated.report().diff.is_empty());
}

#[test]
fn equivalent_http_selector_reuses_existing_rule_even_when_name_and_proof_change() {
    let fixture = Fixture::new(report_with_unused());
    plan_background_dependency(fixture.feedback())
        .unwrap()
        .apply()
        .unwrap();

    let mut feedback = fixture.feedback();
    feedback.name = "another-config-refresh".to_string();
    feedback.source_revision = "fedcba9876543210".to_string();
    feedback.source_evidence = "src/other.rs:9 same process-owned refresh".to_string();
    let plan = plan_background_dependency(feedback).unwrap();

    assert!(plan.report().reused_existing);
    assert_eq!(plan.report().effective_name, "config-refresh");
    assert!(!plan.report().changed);
    assert!(plan.report().diff.is_empty());
    let applied = plan.apply().unwrap();
    assert!(applied.applied);
    assert!(applied.reused_existing);

    let config = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
    assert_eq!(config.process_owned_dependencies.len(), 1);
    assert_eq!(
        config.process_owned_dependencies[0].name(),
        "config-refresh"
    );
}

#[test]
fn covered_http_selector_reuses_a_multi_selector_system_default() {
    let fixture = Fixture::new(report_with_unused());
    fs::write(
        &fixture.config,
        SourceTrafficPolicyConfig::repository_defaults()
            .render()
            .unwrap(),
    )
    .unwrap();

    let plan = plan_background_dependency(fixture.feedback()).unwrap();

    assert!(plan.report().reused_existing);
    assert_eq!(plan.report().effective_name, "breeze_vintage");
    assert!(!plan.report().changed);
    assert!(plan.report().diff.is_empty());
}

#[test]
fn rejects_incomplete_or_conflicting_replay_evidence() {
    let mut report = report_with_unused();
    report["finalized"] = json!(false);
    let fixture = Fixture::new(report);
    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("finalized")
    );

    let mut report = report_with_unused();
    report["unused_case_http_exchanges"] = json!([]);
    let fixture = Fixture::new(report);
    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("matches no unused")
    );

    let mut report = report_with_unused();
    report["unmatched_http_requests"] = json!([evidence(
        "case-a",
        "config.api.demo.test",
        80,
        "GET",
        "/1/config/service?action=write",
    )]);
    let fixture = Fixture::new(report);
    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("unmatched target")
    );

    let mut report = report_with_unused();
    report["unsupported_http_exchanges"] = json!([evidence(
        "case-a",
        "config.api.demo.test",
        80,
        "GET",
        "/1/config/service?action=unsupported",
    )]);
    let fixture = Fixture::new(report);
    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("unsupported target")
    );
}

#[test]
fn apply_rejects_stale_rules_or_replay_report() {
    let fixture = Fixture::new(report_with_unused());
    let plan = plan_background_dependency(fixture.feedback()).unwrap();
    fs::write(&fixture.config, "version: 1\n# drift\n").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("process-owned rules changed")
    );

    let fixture = Fixture::new(report_with_unused());
    let plan = plan_background_dependency(fixture.feedback()).unwrap();
    let mut report = report_with_unused();
    report["selected_case_ids"] = json!(["case-a"]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("replay report changed")
    );
}

#[test]
fn existing_name_cannot_be_reused_for_a_different_selector() {
    let fixture = Fixture::new(report_with_unused());
    plan_background_dependency(fixture.feedback())
        .unwrap()
        .apply()
        .unwrap();

    let mut feedback = fixture.feedback();
    feedback.path_prefix = "/1/config".to_string();
    assert!(
        plan_background_dependency(feedback)
            .unwrap_err()
            .to_string()
            .contains("different selector")
    );
}

#[test]
fn rejects_unknown_fields_in_the_source_traffic_policy() {
    let fixture = Fixture::new(report_with_unused());
    fs::write(&fixture.config, "version: 1\nowner: manual\n").unwrap();

    assert!(
        plan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("failed to parse unified traffic policy")
    );
}
