use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

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
fn action_commands_are_argv_and_do_not_contain_secret_values() {
    let state = test_state();
    let target = Path::new("/target");
    let value = serde_json::to_value(action::for_state(target, &state)).unwrap();
    assert_eq!(value.get("schema_version"), Some(&serde_json::json!(34)));
    assert!(value.get("source_process_traffic").is_none());
    assert!(value.get("process_output_inventory").is_none());
    assert!(value.get("latest_focused_e2e").is_none());
    assert_eq!(
        value.pointer("/action/commands/execute/cwd"),
        Some(&serde_json::json!(target))
    );
    assert!(
        value
            .pointer("/action/commands/execute/required_env_names")
            .is_none()
    );
    assert_eq!(
        value.pointer("/action/commands/execute/argv/0"),
        Some(&Value::String("backend-rewrite".to_string()))
    );
    assert_eq!(
        value.pointer("/action/commands/execute/argv/1"),
        Some(&serde_json::json!("--target-root"))
    );
    assert_eq!(
        value.pointer("/action/commands/execute/argv/2"),
        Some(&serde_json::json!("/target"))
    );
    assert_eq!(
        value.pointer("/action/commands/execute/argv/4"),
        Some(&serde_json::json!("execute"))
    );
    assert_eq!(
        value
            .pointer("/action/commands/execute/argv")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert!(!value.to_string().contains("encryption-key-value"));
}

#[test]
fn rejected_recording_action_allocates_a_replacement_without_exposing_paths() {
    let mut state = test_state();
    state.recording_rejection = Some(artifacts::recording_rejection(&anyhow::anyhow!(
        "standard recording published no cases"
    )));
    state.recording_run_id = "20260802000001".to_string();

    let target = Path::new("/target");
    let value = serde_json::to_value(action::for_state(target, &state)).unwrap();
    assert_eq!(
        value.pointer("/action/commands/execute/argv/5"),
        Some(&serde_json::json!(recording_action::recording_action_id(
            &state, false
        )))
    );
    let summary = value.pointer("/action/summary").unwrap().as_str().unwrap();
    assert!(summary.contains("published no cases"));
    assert!(!summary.contains(".traffic-e2e"));
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
fn clean_reclassification_advances_without_replacing_standard_recording() {
    let target = tempfile::tempdir().unwrap();
    fs::write(
        target.path().join("Cargo.toml"),
        "[package]\nname='target'\n",
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
        },
        progress: PathBuf::from("replay-progress.yaml"),
        runtime_outputs: Vec::new(),
    };

    transition::from_e2e_result(
        target.path(),
        &mut state,
        &result,
        transition::AttemptTransition::ReclassifyCurrent,
    )
    .unwrap();

    assert_eq!(state.phase, RewritePhase::ComparisonRecordingRequired);
    assert_eq!(state.recording_run_id, "20260803023812");
    assert_eq!(state.recording_request_reason, None);
    assert_eq!(state.attempts.len(), 1);
    assert!(state.attempts[0].passed);
    assert!(state.comparison_run_id.is_some());
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
    test_support::install_project_config(
        target.path(),
        "integration",
        test_support::managed_test_recorder(),
        Some(serde_json::json!([])),
    );
    fs::write(
        target.path().join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
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
