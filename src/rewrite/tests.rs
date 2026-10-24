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
    test_support::install_project_config(
        target.path(),
        "integration",
        test_support::managed_test_recorder(),
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
fn clean_reclassification_advances_without_replacing_standard_recording() {
    let (target, mut state, result) = reclassification_fixture();
    let mut failed = result.clone();
    failed.passed = false;
    failed.gates.dependencies = crate::E2eDependencyGate::Dirty;
    state.attempts.clear();
    transition::from_e2e_result(
        target.path(),
        &mut state,
        &failed,
        transition::AttemptTransition::Append,
    )
    .unwrap();

    transition::from_e2e_result(
        target.path(),
        &mut state,
        &result,
        transition::AttemptTransition::ReclassifyCurrent,
    )
    .unwrap();
    assert_eq!(state.phase, RewritePhase::SliceComplete);
    assert_eq!(state.recording_run_id, "20260803023812");
    assert_eq!(state.recording_request_reason, None);
    assert_eq!(state.attempts.len(), 1);
    assert!(state.attempts[0].passed);
}

#[test]
fn reclassification_after_code_change_requests_replay_without_stamping_new_code() {
    let (target, mut state, result) = reclassification_fixture();
    let mut failed = result.clone();
    failed.passed = false;
    failed.gates.dependencies = crate::E2eDependencyGate::Dirty;
    state.attempts.clear();
    transition::from_e2e_result(
        target.path(),
        &mut state,
        &failed,
        transition::AttemptTransition::Append,
    )
    .unwrap();
    let original = state.target_fingerprint.clone();
    fs::write(
        target.path().join("Cargo.toml"),
        "[package]\nname='changed-target'\n",
    )
    .unwrap();
    assert_ne!(
        original.as_deref(),
        Some(
            fingerprint::repository_fingerprint(target.path())
                .unwrap()
                .as_str()
        )
    );
    transition::from_e2e_result(
        target.path(),
        &mut state,
        &result,
        transition::AttemptTransition::ReclassifyCurrent,
    )
    .unwrap();
    assert_eq!(state.target_fingerprint, original);
    assert!(!state.e2e_current);
    assert_eq!(state.phase, RewritePhase::ApiPending);
    assert!(state.active_issue.is_none());
    assert_eq!(state.attempts.len(), 1);
}

#[test]
fn reclassification_reuses_only_classification_changes_and_never_upgrades_legacy_evidence() {
    for change in [
        "classification",
        "verification",
        "startup",
        "environment",
        "legacy",
    ] {
        let (target, mut state, result) = reclassification_fixture();
        state.attempts.clear();
        let mut failed = result.clone();
        failed.passed = false;
        failed.gates.dependencies = crate::E2eDependencyGate::Dirty;
        transition::from_e2e_result(
            target.path(),
            &mut state,
            &failed,
            transition::AttemptTransition::Append,
        )
        .unwrap();
        let original = state.target_fingerprint.clone();
        match change {
            "classification" => {
                crate::e2e_run::test_session::classify_stream(target.path());
            }
            "verification" => {
                let document = serde_json::json!({"format":"traffic-policy/v2","rules":[{
                    "id":"response-items","surface":"api.response","match":{"api":"GET /api"},
                    "slot":"body","codec":"json","contract":{"/items":{"kind":"unordered"}},
                    "proof":{"source":"handler.rs:12","fact":"Source emits these items from a set"}
                }]});
                crate::policy::compile_policy(&serde_json::from_value(document.clone()).unwrap())
                    .unwrap();
                fs::write(
                    target.path().join(".traffic-e2e/policy.yaml"),
                    serde_yaml::to_string(&document).unwrap(),
                )
                .unwrap();
            }
            "startup" => {
                let path = target
                    .path()
                    .join(crate::repository::LOCAL_STARTUP_MANIFEST_PATH);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(
                    path,
                    serde_json::to_vec(&serde_json::json!({
                        "schema_version": 4,
                        "snapshot_id": "new-snapshot",
                        "content_revision": "new-content",
                        "source_snapshot_id": "source",
                        "source_image_id": "image",
                        "mounts": []
                    }))
                    .unwrap(),
                )
                .unwrap();
            }
            "environment" => {
                crate::startup::ensure_startup_environment(
                    target.path(),
                    "REGRESSION_MODE",
                    "changed",
                )
                .unwrap();
            }
            _ => {
                let mut encoded = serde_json::to_value(&state).unwrap();
                encoded.as_object_mut().unwrap().remove("replay_identity");
                state = serde_json::from_value(encoded).unwrap();
            }
        }
        transition::from_e2e_result(
            target.path(),
            &mut state,
            &result,
            transition::AttemptTransition::ReclassifyCurrent,
        )
        .unwrap();
        if change == "classification" {
            assert!(state.e2e_current);
            assert_eq!(state.phase, RewritePhase::SliceComplete);
            assert_eq!(
                state.target_fingerprint,
                Some(fingerprint::repository_fingerprint(target.path()).unwrap())
            );
        } else {
            assert!(!state.e2e_current);
            assert_eq!(state.phase, RewritePhase::ApiPending);
            assert_eq!(state.target_fingerprint, original);
        }
    }
}

fn reclassification_fixture() -> (
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
        "format: traffic-policy/v2\nrules: []\n",
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

    (target, state, result)
}
