use std::fs;
use std::path::{Path, PathBuf};

use super::super::recording_action::recording_action_id;
use super::super::{artifacts, recording_execution};
use super::*;
use crate::{
    E2eDependencyGate, E2eDiagnosisCounts, E2eReplayGate, E2eResponseGate, E2eVerificationGates,
};

use super::super::model::{
    RewriteAttemptSummary, RewriteDependencyRulePlanRecord, RewriteDependencyRuleSpec,
    RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewriteRecordingReason,
    RewriteRepairAcceptanceKind, RewriteRouteRecord, RewriteRulePlanRecord,
};

#[test]
fn cross_api_non_preemptible_transition_returns_bounded_wait() {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ComparisonRecordingRequired;
    state.comparison_run_id = Some("20260907000000".into());
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

#[test]
fn status_recovers_the_exact_recording_action_until_a_result_exists() {
    let target = tempfile::tempdir().unwrap();
    let mut state = crate::rewrite::test_state();

    let pending = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
    assert_eq!(
        pending.pointer("/action/kind"),
        Some(&serde_json::json!("recording_required"))
    );
    assert_eq!(
        pending.pointer("/action/details/run_id"),
        Some(&serde_json::json!(state.recording_run_id.as_str()))
    );
    assert_eq!(
        pending.pointer("/action/commands/execute/cwd"),
        Some(&serde_json::json!(target.path()))
    );
    assert!(
        pending
            .pointer("/action/commands/execute/argv/5")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.starts_with("recording-"))
    );

    let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(
            manifest,
            br#"{"status":"completed","recording_apis":["GET /api"],"published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
    let advanceable = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
    assert_eq!(
        advanceable.pointer("/action/kind"),
        Some(&serde_json::json!("advance_required"))
    );
    assert_eq!(
        advanceable.pointer("/action/commands/advance/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            target.path(),
            "next",
            "--api",
            "/api"
        ]))
    );

    state.phase = RewritePhase::ComparisonRecordingRequired;
    state.comparison_run_id = Some("20260802000001".to_string());
    let comparison_pending =
        serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
    assert_eq!(
        comparison_pending.pointer("/action/kind"),
        Some(&serde_json::json!("comparison_recording_required"))
    );
    assert_eq!(
        comparison_pending.pointer("/action/details/run_id"),
        Some(&serde_json::json!("20260802000001"))
    );
    assert_eq!(
        comparison_pending.pointer("/action/commands/execute/argv/5"),
        Some(&serde_json::json!(recording_action_id(&state, true)))
    );

    let comparison_manifest = artifacts::comparison_manifest(target.path(), "20260802000001");
    fs::create_dir_all(comparison_manifest.parent().unwrap()).unwrap();
    fs::write(
            comparison_manifest,
            br#"{"status":"completed","ready":true,"recording_apis":["GET /api"],"counts":{"published":1,"failed":0},"errors":[]}"#,
        )
        .unwrap();
    let comparison_advanceable =
        serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
    assert_eq!(
        comparison_advanceable.pointer("/action/kind"),
        Some(&serde_json::json!("advance_required"))
    );
}

#[test]
fn api_scoped_status_observes_recording_publication() {
    for comparison in [false, true] {
        let target = super::super::worker::tests::configured_target();
        let mut state = crate::rewrite::test_state();
        state.target_fingerprint =
            Some(super::super::fingerprint::repository_fingerprint(target.path()).unwrap());
        let (manifest, pending_kind) = if comparison {
            fs::write(
                target.path().join(crate::config::regression::PATH),
                "require_comparison: true\n",
            )
            .unwrap();
            state.require_comparison = true;
            state.phase = RewritePhase::ComparisonRecordingRequired;
            state.comparison_run_id = Some("20260802000001".into());
            state.e2e_current = true;
            (
                artifacts::comparison_manifest(target.path(), "20260802000001"),
                "comparison_recording_required",
            )
        } else {
            (
                artifacts::recording_manifest(target.path(), &state.recording_run_id),
                "recording_required",
            )
        };
        let store = super::super::store::RewriteStore::new(target.path()).unwrap();
        store.save(&state).unwrap();
        let persisted = serde_json::to_value(store.load().unwrap()).unwrap();
        let api = state.api.parse().unwrap();
        let check = |kind: &str| {
            let scoped = super::super::status_rewrite_for_api(
                super::super::RewriteContext {
                    target_root: target.path().into(),
                },
                Some(&api),
            )
            .unwrap();
            let global = super::super::status_rewrite(super::super::RewriteContext {
                target_root: target.path().into(),
            })
            .unwrap();
            let scoped = serde_json::to_value(scoped.action).unwrap();
            assert_eq!(scoped["kind"], kind, "comparison={comparison}");
            assert_eq!(scoped, serde_json::to_value(global.action).unwrap());
            assert_eq!(
                serde_json::to_value(store.load().unwrap()).unwrap(),
                persisted
            );
            scoped
        };
        check(pending_kind);

        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        let publication = |status: &str| {
            serde_json::to_vec(&serde_json::json!({
                "status": status,
                "recording_apis": ["GET /api"],
                "ready": true,
                "published_cases": 1,
                "failed_cases": 0,
                "counts": {"published": 1, "failed": 0},
                "errors": []
            }))
            .unwrap()
        };
        fs::write(&manifest, publication("running")).unwrap();
        check("recovery_required");

        let action_id = recording_action_id(&state, comparison);
        recording_execution::publish(
            target.path(),
            &recording_execution::RecordingExecutionMarker {
                action_id: action_id.clone(),
                run_id: if comparison {
                    state.comparison_run_id.clone().unwrap()
                } else {
                    state.recording_run_id.clone()
                },
                operation: if comparison {
                    "record-comparison"
                } else {
                    "record"
                }
                .into(),
                pid: std::process::id(),
            },
        )
        .unwrap();
        check("recording_in_progress");

        fs::write(&manifest, publication("completed")).unwrap();
        check("recording_in_progress");
        recording_execution::clear(target.path(), &action_id).unwrap();
        let finalized = check("advance_required");
        assert_eq!(
            finalized["commands"]["advance"]["argv"],
            serde_json::json!([
                "backend-rewrite",
                "--target-root",
                target.path(),
                "next",
                "--api",
                "/api"
            ])
        );
    }
}

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
fn status_requires_recovery_for_an_unowned_running_manifest() {
    let target = tempfile::tempdir().unwrap();
    let state = crate::rewrite::test_state();
    let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(
            manifest,
            br#"{"status":"running","recording_apis":["GET /api"],"published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();

    let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
    assert_eq!(
        status.pointer("/action/kind"),
        Some(&serde_json::json!("recovery_required"))
    );
    assert_eq!(
        status.pointer("/action/commands/recover/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            target.path(),
            "recover"
        ]))
    );
}

#[test]
fn status_reports_a_live_recording_without_returning_execute_again() {
    let target = tempfile::tempdir().unwrap();
    let state = crate::rewrite::test_state();
    let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(
            manifest,
            br#"{"status":"running","recording_apis":[],"observed_api_count":2,"published_cases":7,"failed_cases":2,"errors":[]}"#,
        )
        .unwrap();
    recording_execution::publish(
        target.path(),
        &recording_execution::RecordingExecutionMarker {
            action_id: recording_action_id(&state, false),
            run_id: state.recording_run_id.clone(),
            operation: "record".to_string(),
            pid: std::process::id(),
        },
    )
    .unwrap();

    let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
    assert_eq!(
        status.pointer("/action/kind"),
        Some(&serde_json::json!("recording_in_progress"))
    );
    assert_eq!(
        status.pointer("/action/details/status_poll_after_seconds"),
        Some(&serde_json::json!(30))
    );
    assert_eq!(
        status.pointer("/action/details/progress"),
        Some(&serde_json::json!({
            "apis": 2,
            "published_cases": 7,
            "failed_cases": 2
        }))
    );
    assert_eq!(
        status.pointer("/action/summary"),
        Some(&serde_json::json!(
            "standard recording run 20260802000000 is executing: 2 APIs, 7 cases published, 2 cases failed"
        ))
    );
    assert_eq!(
        status.pointer("/action/commands/wait/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            target.path(),
            "wait",
            "--seconds",
            "30"
        ]))
    );
    assert!(status.pointer("/action/commands/execute").is_none());
}

#[test]
fn recording_action_id_is_stable_and_bound_to_the_request_corpus() {
    let mut state = crate::rewrite::test_state();
    let original = recording_action_id(&state, false);

    state.bump();
    assert_eq!(recording_action_id(&state, false), original);

    state.recording_input_case_source = Some(PathBuf::from("another-recording"));
    assert_ne!(recording_action_id(&state, false), original);

    state.recording_request_reason = Some(RewriteRecordingReason::RecorderContractChanged);
    let fresh = recording_action_id(&state, false);
    state.recording_input_case_source = Some(PathBuf::from("ignored-old-recording"));
    assert_eq!(recording_action_id(&state, false), fresh);

    let status = serde_json::to_value(for_state(Path::new("/target"), &state)).unwrap();
    assert_eq!(
        status.pointer("/action/details/input_mode"),
        Some(&serde_json::json!("external_live_traffic"))
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
        comparison_observation: None,
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
