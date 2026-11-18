use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;

#[test]
fn pointer_patterns_replace_only_array_indices() {
    assert_eq!(
        crate::e2e_run::response_pointer_pattern("/users/17/id"),
        "/users/*/id"
    );
    assert_eq!(
        crate::e2e_run::response_pointer_pattern("/v2/created_at"),
        "/v2/created_at"
    );
}

#[test]
fn recording_requirements_are_external_inputs_without_execution_commands() {
    let mut state = test_state();
    let target = Path::new("/target");
    for rejected in [false, true] {
        state.recording_rejection =
            rejected.then(|| "standard recording published no cases".to_owned());
        let value = serde_json::to_value(action::for_state(target, &state)).unwrap();
        assert_eq!(value["action"]["kind"], "input_required");
        assert_eq!(
            value["action"]["details"]["reason"],
            "recording_evidence_required"
        );
        assert_eq!(value["action"]["commands"], serde_json::json!({}));
        assert!(!value.to_string().contains("encryption-key-value"));
    }
}

#[test]
fn status_mismatch_causes_do_not_suggest_collection_or_dynamic_rules() {
    let causes =
        issue::response_possible_causes(Some(crate::ResponseDifferenceKind::StatusMismatch));
    assert!(causes.iter().any(|cause| cause.contains("authentication")));
    assert!(!causes.iter().any(|cause| cause.contains("collection")));
    assert!(!causes.iter().any(|cause| cause.contains("nondeterminism")));
}

#[test]
fn incomplete_work_never_allows_terminal_output() {
    let state = test_state();
    assert!(!action::for_state(Path::new("/target"), &state).terminal_allowed);
}

#[test]
fn stale_workflow_returns_only_a_public_recovery_command() {
    let target = Path::new("/target");
    let value = serde_json::to_value(action::recovery_required(target)).unwrap();
    assert_eq!(
        value.pointer("/action/commands/recover/argv"),
        Some(&serde_json::json!([
            "backend-rewrite",
            "--target-root",
            "/target",
            "recover"
        ]))
    );
    assert_eq!(
        value.pointer("/action/commands/recover/cwd"),
        Some(&serde_json::json!(target))
    );
    assert!(!value.to_string().contains(".traffic-e2e/local/runtime"));
    assert!(value.pointer("/action/commands/advance").is_none());
}

#[test]
fn project_resolution_cache_is_stable_only_inside_its_read_scope() {
    let target = tempfile::tempdir().unwrap();
    workflow_test_support::install_project_config(
        target.path(),
        "integration",
        workflow_test_support::managed_test_recorder(),
        Some(serde_json::json!([])),
    );
    git_ok(target.path(), &["init", "-q", "-b", "integration"]);
    git_ok(target.path(), &["config", "user.email", "test@example.com"]);
    git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
    git_ok(target.path(), &["add", "."]);
    git_ok(target.path(), &["commit", "-m", "baseline"]);
    git_ok(target.path(), &["switch", "-q", "-c", "feature"]);

    crate::e2e_run::with_project_resolution_cache(|| {
        crate::e2e_run::resolve_project(target.path()).unwrap();
        git_ok(target.path(), &["branch", "-D", "integration"]);
        crate::e2e_run::resolve_project(target.path()).unwrap();
    });

    let error = crate::e2e_run::resolve_project(target.path()).unwrap_err();
    assert!(error.to_string().contains("pr_base"));
    assert!(error.to_string().contains("does not exist"));
}

fn git_ok(repository: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {args:?}");
}

#[test]
fn changed_retry_case_count_does_not_report_a_response_regression() {
    let (target, mut state, mut result) = execution_fixture();
    state.attempts.clear();
    for (selected, response_passed, response_nonpassing) in [(5, 2, 3), (3, 3, 0), (3, 1, 2)] {
        result.attempt += 1;
        result.diagnosis.counts.selected = selected;
        result.diagnosis.counts.executed = selected;
        result.diagnosis.counts.response_passed = response_passed;
        result.diagnosis.counts.response_nonpassing = response_nonpassing;
        transition::from_e2e_result(target.path(), &mut state, &result).unwrap();
        if state.attempts.len() <= 2 {
            assert!(state.attempt_delta.is_none());
        }
    }
    assert!(state.attempt_delta.as_ref().unwrap().regressed);
}

#[test]
fn historical_report_cannot_promote_or_replace_a_real_failed_attempt() {
    let (target, mut state, result) = execution_fixture();
    state.attempts.clear();
    let mut failed = result.clone();
    failed.passed = false;
    failed.gates.dependencies = crate::E2eDependencyGate::Dirty;
    transition::from_e2e_result(target.path(), &mut state, &failed).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    assert!(
        transition::from_e2e_result(target.path(), &mut state, &result)
            .unwrap_err()
            .to_string()
            .contains("new actual Replay")
    );
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
}

fn execution_fixture() -> (
    tempfile::TempDir,
    model::RewriteState,
    crate::E2eApiRunResult,
) {
    let target = tempfile::tempdir().unwrap();
    fs::write(
        target.path().join("Cargo.toml"),
        "[package]\nname='target'\n",
    )
    .unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    fs::write(
        target.path().join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v3\nrules: []\n",
    )
    .unwrap();
    git_ok(target.path(), &["init"]);
    git_ok(target.path(), &["config", "user.email", "test@example.com"]);
    git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
    git_ok(target.path(), &["add", "."]);
    git_ok(target.path(), &["commit", "-m", "baseline"]);

    let counts = crate::E2eDiagnosisCounts {
        selected: 10,
        executed: 10,
        response_passed: 10,
        response_nonpassing: 0,
        response_incomplete: 0,
    };
    let mut state = test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.recording_run_id = "20260803023812".to_string();
    state.case_source = Some(PathBuf::from("recording-cases"));
    state.group_id = Some("GET /api".to_string());
    state.attempts.push(model::RewriteAttemptSummary {
        engine_fingerprint: None,
        attempt: 3,
        passed: false,
        gates: crate::E2eVerificationGates {
            responses: crate::E2eResponseGate::Passed,
            replay: crate::E2eReplayGate::Complete,
            dependencies: crate::E2eDependencyGate::Dirty,
        },
        counts: counts.clone(),
    });
    let result = crate::E2eApiRunResult {
        engine_fingerprint: None,
        run_key: "20260803023812".to_string(),
        api: "GET /api".to_string(),
        attempt: 3,
        status: "successful".to_string(),
        passed: true,
        gates: crate::E2eVerificationGates {
            responses: crate::E2eResponseGate::Passed,
            replay: crate::E2eReplayGate::Complete,
            dependencies: crate::E2eDependencyGate::Clean,
        },
        diagnosis: crate::E2eDiagnosis {
            case_selection: None,
            replay_finalized: None,
            egress_rejections: None,
            counts,
            response_differences: crate::E2eResponseDifferenceDiagnosis {
                total_differences: 0,
                indexed_differences: 0,
                omitted_differences: 0,
                failure_clusters: Vec::new(),
                omitted_failure_clusters: 0,
            },
            representative: None,
            lifecycle_errors: Vec::new(),
            execution_failures: Vec::new(),
        },
        progress: PathBuf::from("replay-progress.yaml"),
        runtime_outputs: Vec::new(),
    };

    (target, state, result)
}
