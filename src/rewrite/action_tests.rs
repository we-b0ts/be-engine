use std::fs;
use std::path::{Path, PathBuf};

use super::super::artifacts;
use super::*;
use crate::{
    E2eDependencyGate, E2eDiagnosisCounts, E2eReplayGate, E2eResponseGate, E2eVerificationGates,
};

use super::super::model::{
    RewriteAttemptSummary, RewriteDependencyRulePlanRecord, RewriteDependencyRuleSpec,
    RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewriteRepairAcceptanceKind,
    RewriteRouteRecord, RewriteRulePlanRecord,
};

#[test]
fn status_recovers_pending_case_pattern_identification_after_recording_finalizes() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.case_pattern_identification =
        Some(super::super::model::RewriteCasePatternIdentification {
            id: "case-patterns-current".to_string(),
            recording_run_id: state.recording_run_id.clone(),
            candidates: vec!["GET /api/tasks/123/tree".to_string()],
            observed_apis: vec!["GET /api/tasks/123/tree".to_string()],
        });
    let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(
        manifest,
        br#"{"status":"completed","recording_apis":["GET /api"],"published_cases":1}"#,
    )
    .unwrap();

    let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();

    assert_eq!(
        status["action"]["kind"],
        serde_json::json!("case_pattern_identification_required")
    );
    assert_eq!(
        status["action"]["details"]["batch_id"],
        serde_json::json!("case-patterns-current")
    );
}

#[test]
fn status_returns_the_coordinator_issued_repair_acceptance() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::SystemRepairRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-replay".to_string(),
        kind: RewriteIssueKind::Replay,
        owner: RewriteIssueOwner::TrafficE2eSystem,
        summary: "replay capability gap".to_string(),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
    });
    state.route = Some(RewriteRouteRecord {
        kind: "replay_capability_gap".to_string(),
        evidence_id: "evidence-replay".to_string(),
        source_ref: "src/replay.rs:1".to_string(),
        required_change: "support the recorded exchange".to_string(),
        repair_id: Some("repair-current".to_string()),
        acceptance_kind: Some(RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged),
        observed_revision: Some("fnv1a64:old".to_string()),
        legacy_acceptance_command: None,
    });

    let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();

    assert_eq!(
        status.pointer("/action/commands/acceptance/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            target.path(),
            "repair",
            "verify",
            "repair-current"
        ]))
    );
    assert_eq!(
        status.pointer("/action/commands/acceptance/cwd"),
        Some(&serde_json::json!(target.path()))
    );
}

#[test]
fn pending_rule_plans_are_recoverable_by_plan_id() {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.rule_plan = Some(RewriteRulePlanRecord {
        response_jwts: Vec::new(),
        header_dates: Vec::new(),
        dynamic_value: None,
        dependency_request: None,
        time: None,
        id: "plan-response".to_string(),
        issue_id: "issue-response".to_string(),
        kind: "uuid".to_string(),
        json_pointer: "/request_id".to_string(),
        source_evidence: Some("src/id.rs:new".to_string()),
        source_example: None,
        target_example: None,
        separator: None,
        response_body: None,
        jwt: None,
        evidence_id: "evidence-response".to_string(),
    });

    let target = Path::new("/target");
    let response = serde_json::to_value(for_state(target, &state)).unwrap();
    assert_eq!(
        response.pointer("/action/kind"),
        Some(&serde_json::json!("plan_apply_required"))
    );
    assert_eq!(
        response.pointer("/action/commands/apply/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            "/target",
            "rule",
            "apply",
            "plan-response"
        ]))
    );

    state.rule_plan = None;
    state.dependency_rule_plan = Some(RewriteDependencyRulePlanRecord {
        review_fingerprint: None,
        id: "plan-dependency".to_string(),
        issue_id: "issue-dependency".to_string(),
        evidence_id: "evidence-dependency".to_string(),
        name: "cache-warm".to_string(),
        source_evidence: "src/cache.rs:warm".to_string(),
        spec: RewriteDependencyRuleSpec::Http {
            authority: "config.internal".to_string(),
            method: "GET".to_string(),
            path_prefix: "/config".to_string(),
        },
        reused_existing: false,
        effective_name: None,
    });
    let dependency = serde_json::to_value(for_state(target, &state)).unwrap();
    assert_eq!(
        dependency.pointer("/action/commands/apply/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            "/target",
            "dependency-rule",
            "apply",
            "plan-dependency"
        ]))
    );

    let plan = state.dependency_rule_plan.as_mut().unwrap();
    plan.reused_existing = true;
    plan.effective_name = Some("existing-cache-warm".to_string());
    let reused = serde_json::to_value(for_state(target, &state)).unwrap();
    assert_eq!(
        reused.pointer("/action/kind"),
        Some(&serde_json::json!("plan_apply_required"))
    );
    assert_eq!(
        reused.pointer("/action/commands/apply/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            "/target",
            "dependency-rule",
            "apply",
            "plan-dependency"
        ]))
    );
    assert!(
        reused
            .pointer("/action/summary")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|summary| summary.contains("existing-cache-warm"))
    );
}

#[test]
fn identifies_fresh_and_reused_standard_cases() {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::SliceComplete;
    state.case_source = Some(PathBuf::from(
        ".traffic-e2e/local/artifacts/recordings/20260802000000",
    ));
    state.case_inventory_id = Some("fnv1a64:case-inventory".to_string());
    state.attempts.push(test_attempt(1, false));

    let target = Path::new("/target");
    let fresh = serde_json::to_value(for_state(target, &state)).unwrap();
    assert_eq!(
        fresh.pointer("/latest_focused_e2e/execution_mode"),
        Some(&serde_json::json!("fresh_standard_cases"))
    );
    assert_eq!(
        fresh.pointer("/latest_focused_e2e/recording_run_id"),
        Some(&serde_json::json!("20260802000000"))
    );
    assert_eq!(
        fresh.pointer("/latest_focused_e2e/case_inventory_id"),
        Some(&serde_json::json!("fnv1a64:case-inventory"))
    );
    assert!(
        fresh
            .pointer("/latest_focused_e2e/previous_attempt")
            .is_none()
    );
    assert_eq!(
        fresh.pointer("/latest_focused_e2e/current_attempt"),
        Some(&serde_json::json!(1))
    );

    state.attempts.push(test_attempt(2, true));
    let reused = serde_json::to_value(for_state(target, &state)).unwrap();
    assert_eq!(
        reused.pointer("/latest_focused_e2e/execution_mode"),
        Some(&serde_json::json!("reused_standard_cases"))
    );
    assert_eq!(
        reused.pointer("/latest_focused_e2e/previous_attempt"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        reused.pointer("/latest_focused_e2e/current_attempt"),
        Some(&serde_json::json!(2))
    );
    assert_eq!(
        reused.pointer("/latest_focused_e2e/passed"),
        Some(&serde_json::json!(true))
    );
}

fn test_attempt(attempt: u64, passed: bool) -> RewriteAttemptSummary {
    RewriteAttemptSummary {
        engine_fingerprint: None,
        attempt,
        passed,
        gates: E2eVerificationGates {
            responses: if passed {
                E2eResponseGate::Passed
            } else {
                E2eResponseGate::Nonpassing
            },
            replay: E2eReplayGate::Complete,
            dependencies: E2eDependencyGate::Clean,
        },
        counts: E2eDiagnosisCounts {
            selected: 1,
            executed: 1,
            response_passed: usize::from(passed),
            response_nonpassing: usize::from(!passed),
            response_incomplete: 0,
        },
    }
}

#[test]
fn cross_api_non_preemptible_transition_returns_bounded_wait() {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::RecordingRequired;
    let target = Path::new("/target");

    let response = serde_json::to_value(api_selection_wait_envelope(
        target,
        &state,
        "POST /other".to_string(),
    ))
    .unwrap();

    assert_eq!(response["action"]["kind"], "wait_required");
    assert_eq!(
        response["action"]["details"]["resource"],
        "rewrite_api_transition"
    );
    assert_eq!(response["action"]["details"]["blocking_api"], "/api");
    assert!(
        response
            .pointer("/action/details/active_operation")
            .is_none()
    );
    assert_eq!(
        response["action"]["commands"]["wait"]["argv"],
        serde_json::json!([
            "backend-rewrite",
            "--target-root",
            "/target",
            "wait",
            "--seconds",
            "5"
        ])
    );
}
