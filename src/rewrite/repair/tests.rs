use std::fs;
use std::process::Command;

use super::*;
use crate::rewrite::model::{RewriteAttemptSummary, RewriteIssueOwner, RewritePhase};
use crate::{
    E2eDependencyGate, E2eDiagnosisCounts, E2eReplayGate, E2eResponseGate, E2eVerificationGates,
};

#[test]
fn traffic_system_comparison_issue_accepts_replay_capability_repair() {
    let mut issue = repair_state("fnv1a64:old".to_string())
        .active_issue
        .clone()
        .unwrap();
    issue.kind = RewriteIssueKind::Comparison;

    validate_route_kind(&issue, "replay_capability_gap").unwrap();

    issue.owner = RewriteIssueOwner::SourceInvestigation;
    assert!(validate_route_kind(&issue, "replay_capability_gap").is_err());
}

#[test]
fn response_replay_repair_requires_dirty_evidence_and_reuses_the_recording() {
    let mut state = repair_state("fnv1a64:old".into());
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    let issue = state.active_issue.as_ref().unwrap();
    validate_route_kind(issue, "replay_capability_gap").unwrap();
    let mut report = super::super::evidence_model::RewriteEvidenceReport {
        schema_version: 4,
        context: None,
        evidence_id: "current".into(),
        issue_id: issue.id.clone(),
        query: "dirty_clusters".into(),
        facts: serde_json::json!({"clusters":[{"protocol":"mysql","count":43}]}),
        applicable_rule_planners: vec![],
        rule_hints: vec![],
        does_not_prove: vec![],
        next_step: String::new(),
        queries: Default::default(),
    };
    validate_response_replay_evidence(issue, "replay_capability_gap", &report).unwrap();
    report.query = "representatives".into();
    assert!(validate_response_replay_evidence(issue, "replay_capability_gap", &report).is_err());
    report.query = "dirty_clusters".into();
    report.facts = serde_json::json!({"clusters":[]});
    assert!(validate_response_replay_evidence(issue, "replay_capability_gap", &report).is_err());
    let source = state.case_source.clone();
    let run_id = state.recording_run_id.clone();
    let target = tempfile::tempdir().unwrap();
    verify(target.path(), &mut state, "repair-current").unwrap();
    assert_eq!(state.case_source, source);
    assert_eq!(state.recording_run_id, run_id);
    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
}

#[test]
fn repair_verification_rejects_stale_ids_and_unchanged_revisions() {
    let target = tempfile::tempdir().unwrap();
    let revision = fingerprint::traffic_e2e_revision().unwrap();
    let mut state = repair_state(revision);

    assert!(verify(target.path(), &mut state, "repair-stale").is_err());
    assert!(verify(target.path(), &mut state, "repair-current").is_err());
    assert_eq!(state.phase, RewritePhase::SystemRepairRequired);
}

#[test]
fn coordinator_verified_revision_change_returns_to_the_same_cases() {
    let target = tempfile::tempdir().unwrap();
    let mut state = repair_state("fnv1a64:old".to_string());

    let action = verify(target.path(), &mut state, "repair-current").unwrap();

    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert!(state.route.is_none());
    assert!(state.target_fingerprint.is_none());
    let scope = super::super::RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    assert!(state.system_repair_accepted);
    assert!(
        super::super::worker::scheduler::acceptance_gate(target.path(), &state, &scope).is_none()
    );
    assert!(!super::super::worker::runtime::scopes(&state).contains(&scope));
    assert!(matches!(
        action.action,
        super::super::model::RewriteAction::AdvanceRequired { .. }
    ));
}

#[test]
fn legacy_external_data_response_blocker_resumes_replay_planning_without_revision_change() {
    let target = tempfile::tempdir().unwrap();
    let mut state = repair_state("unchanged-runtime-inputs".to_string());
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
    state.route.as_mut().unwrap().kind = "external_data_blocker".to_string();
    state.route.as_mut().unwrap().acceptance_kind =
        Some(RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged);

    let command = pending_command(target.path(), &state).unwrap();
    assert!(
        command
            .argv
            .iter()
            .any(|arg| arg == "resume-replay-planning")
    );
    let action = resume_replay_planning(target.path(), &mut state, "repair-current").unwrap();

    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert!(state.route.is_none());
    assert!(state.target_fingerprint.is_none());
    assert!(matches!(
        action.action,
        super::super::model::RewriteAction::AdvanceRequired { .. }
    ));
}

#[test]
fn administrator_can_cancel_a_misrouted_source_change_repair() {
    let target = tempfile::tempdir().unwrap();
    let mut state = repair_state("source-revision".to_string());
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Comparison;
    state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
    state.route.as_mut().unwrap().kind = "source_change".to_string();
    state.route.as_mut().unwrap().acceptance_kind =
        Some(RewriteRepairAcceptanceKind::SourceRevisionChanged);
    let revision = state.revision;

    let action = cancel_misroute(
        target.path(),
        &mut state,
        "repair-current",
        "comparison evidence was misclassified",
    )
    .unwrap();

    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert_eq!(
        state.active_issue.as_ref().map(|issue| issue.owner),
        Some(RewriteIssueOwner::TargetCode)
    );
    assert!(state.route.is_none());
    assert_eq!(state.revision, revision + 1);
    assert!(matches!(
        action.action,
        super::super::model::RewriteAction::AdvanceRequired { .. }
    ));
}

#[test]
fn administrator_can_cancel_a_misrouted_capability_repair() {
    let target = tempfile::tempdir().unwrap();
    for (route_kind, issue_kind) in [
        ("replay_capability_gap", RewriteIssueKind::Replay),
        ("replay_capability_gap", RewriteIssueKind::Dependency),
        ("replay_capability_gap", RewriteIssueKind::Response),
        ("recorder_capability_gap", RewriteIssueKind::Response),
        ("recorder_capability_gap", RewriteIssueKind::Dependency),
    ] {
        let mut state = repair_state("traffic-e2e-revision".to_string());
        state.active_issue.as_mut().unwrap().kind = issue_kind;
        state.route.as_mut().unwrap().kind = route_kind.to_string();
        let revision = state.revision;

        let action = cancel_misroute(
            target.path(),
            &mut state,
            "repair-current",
            "target behavior caused the observed mismatch",
        )
        .unwrap();

        assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        assert_eq!(
            state.active_issue.as_ref().map(|issue| issue.owner),
            Some(RewriteIssueOwner::TargetCode)
        );
        assert!(state.route.is_none());
        assert_eq!(state.revision, revision + 1);
        assert!(matches!(
            action.action,
            super::super::model::RewriteAction::AdvanceRequired { .. }
        ));
    }
}

#[test]
fn repair_cancellation_rejects_wrong_id_incompatible_issue_and_external_data_routes() {
    let target = tempfile::tempdir().unwrap();
    let mut state = repair_state("revision".to_string());

    assert!(cancel_misroute(target.path(), &mut state, "repair-stale", "misroute").is_err());

    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::TargetRuntime;
    assert!(cancel_misroute(target.path(), &mut state, "repair-current", "misroute").is_err());

    state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
    state.route.as_mut().unwrap().kind = "external_data_blocker".to_string();
    state.route.as_mut().unwrap().acceptance_kind =
        Some(RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged);
    assert!(cancel_misroute(target.path(), &mut state, "repair-current", "misroute").is_err());
    assert_eq!(state.phase, RewritePhase::SystemRepairRequired);
    assert!(state.route.is_some());
}

#[test]
fn administrator_can_rearm_replay_after_a_matching_out_of_band_run() {
    let target = committed_target();
    let target_fingerprint = fingerprint::repository_fingerprint(target.path()).unwrap();
    let mut state = out_of_band_retry_state(&target_fingerprint);
    let options = retry_options();
    let observed = crate::e2e_run::E2eFocusedAttemptSummary {
        attempt: 13,
        passed: true,
        case_source: PathBuf::from("/cases"),
        case_inventory_id: "inventory".to_string(),
    };

    let action =
        retry_replay_after_out_of_band_run(target.path(), &mut state, &options, &observed).unwrap();

    assert!(state.target_fingerprint.is_none());
    assert!(!state.e2e_current);
    assert!(!state.comparison_current);
    assert!(matches!(
        action.action,
        super::super::model::RewriteAction::AdvanceRequired { .. }
    ));
}

#[test]
fn replay_retry_rejects_a_changed_target_or_nonpassing_external_attempt() {
    let target = committed_target();
    let target_fingerprint = fingerprint::repository_fingerprint(target.path()).unwrap();
    let options = retry_options();
    let mut state = out_of_band_retry_state(&target_fingerprint);
    let nonpassing = crate::e2e_run::E2eFocusedAttemptSummary {
        attempt: 13,
        passed: false,
        case_source: PathBuf::from("/cases"),
        case_inventory_id: "inventory".to_string(),
    };
    assert!(
        retry_replay_after_out_of_band_run(target.path(), &mut state, &options, &nonpassing)
            .is_err()
    );

    let mut state = out_of_band_retry_state(&target_fingerprint);
    fs::write(target.path().join("src.rs"), "fn changed() {}\n").unwrap();
    let passing = crate::e2e_run::E2eFocusedAttemptSummary {
        passed: true,
        ..nonpassing
    };
    assert!(
        retry_replay_after_out_of_band_run(target.path(), &mut state, &options, &passing).is_err()
    );
}

fn repair_state(observed_revision: String) -> RewriteState {
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
        observed_revision: Some(observed_revision),
        legacy_acceptance_command: None,
    });
    state
}

fn out_of_band_retry_state(target_fingerprint: &str) -> RewriteState {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.api = "MOTAN /rpc/example".to_string();
    state.case_source = Some(PathBuf::from("/cases"));
    state.case_inventory_id = Some("inventory".to_string());
    state.target_fingerprint = Some(target_fingerprint.to_string());
    state.attempts.push(RewriteAttemptSummary {
        attempt: 12,
        passed: false,
        gates: E2eVerificationGates {
            responses: E2eResponseGate::Nonpassing,
            replay: E2eReplayGate::Complete,
            dependencies: E2eDependencyGate::Clean,
        },
        counts: E2eDiagnosisCounts {
            selected: 10,
            executed: 10,
            response_passed: 0,
            response_nonpassing: 10,
            response_incomplete: 0,
        },
    });
    state.active_issue = Some(RewriteIssue {
        id: "issue-response".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response assertion could not be evaluated".to_string(),
        pointer_pattern: Some("$response".to_string()),
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: vec!["response_assertion_evaluation_or_evidence_failure".to_string()],
        observed_target_fingerprint: target_fingerprint.to_string(),
        attempt: 12,
        comparison_observation: None,
    });
    state
}

fn retry_options() -> RewriteReplayRetryOptions {
    RewriteReplayRetryOptions {
        target_root: PathBuf::from("/target"),
        api: "MOTAN /rpc/example".to_string(),
        failed_attempt: 12,
        out_of_band_attempt: 13,
        reason: "focused Replay was run outside the coordinator".to_string(),
        confirm_out_of_band_run: true,
    }
}

fn committed_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    git_ok(target.path(), &["init", "-q"]);
    git_ok(target.path(), &["config", "user.email", "test@example.com"]);
    git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
    git_ok(target.path(), &["add", "."]);
    git_ok(target.path(), &["commit", "-q", "-m", "baseline"]);
    target
}

fn git_ok(repository: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}
