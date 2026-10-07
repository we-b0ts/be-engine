use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::model::{RewriteApiStatus, RewritePhase, RewriteState};
use super::store::RewriteStore;
use super::transition::{self, AttemptTransition};
use super::{action, fingerprint, inventory, regression_scope};

fn policy(root: &Path, value: &str) {
    fs::write(root.join(regression_scope::PATH), value).unwrap();
}

#[tokio::test]
async fn public_status_and_next_skip_requested_api_without_recording_or_dispatch() {
    let target = target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = super::test_state();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();
    store.save(&state).unwrap();
    policy(target.path(), "only: []\nskip: [GET /a]\n");
    let api = "GET /a".parse().unwrap();
    let status = super::status_rewrite_for_api(
        super::RewriteContext {
            target_root: target.path().into(),
        },
        Some(&api),
    )
    .unwrap();
    assert!(matches!(
        status.action,
        super::RewriteAction::Complete {
            e2e_current: false,
            comparison_current: false,
            ..
        }
    ));
    assert!(!status.e2e_current);
    assert!(!status.comparison_current);
    let inventory = super::inventory_rewrite(super::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(
        inventory.api_inventory.unwrap().items[0].status,
        RewriteApiStatus::Skipped
    );
    let action = super::next_rewrite(super::RewriteNextOptions {
        target_root: target.path().into(),
        api: Some(api.into()),
        process_output: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        action.action,
        super::RewriteAction::Complete { .. }
    ));
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.api, "GET /b");
    assert!(saved.attempts.is_empty());
    assert!(saved.worker_bindings.is_empty());
    assert_eq!(saved.recording_run_id, state.recording_run_id);
}

#[tokio::test]
async fn default_requires_comparison_and_current_config_overrides_legacy_batch_flags() {
    let target = target();
    assert!(
        next(target.path())
            .await
            .workflow
            .unwrap()
            .require_comparison
    );
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
    pass_api(target.path(), &mut state);
    assert_eq!(state.phase, RewritePhase::ComparisonRecordingRequired);
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
    let run = state.recording_run_id.clone();
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy["recording_require_comparison"] = serde_json::json!(true);
    state = serde_json::from_value(legacy).unwrap();
    store.save(&state).unwrap();

    policy(target.path(), "require_comparison: false\n");
    next(target.path()).await;
    let state = store.load().unwrap().unwrap();
    assert!(!state.require_comparison);
    assert_eq!(state.recording_run_id, run);
    assert_eq!(state.phase, RewritePhase::SliceComplete);
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
    assert!(state.e2e_current);
    assert!(!state.comparison_current);
}

#[tokio::test]
async fn scoped_replay_only_completion_is_terminal_and_enabling_comparison_reuses_replay() {
    let target = target();
    git(target.path(), &["switch", "-qc", "rewrite-feature"]);
    policy(target.path(), "only: [GET /b]\nrequire_comparison: false\n");
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = super::test_state();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();
    regression_scope::apply(target.path(), &mut state).unwrap();
    assert_eq!(state.api, "GET /b");
    pass_api(target.path(), &mut state);
    write_progress(target.path(), &state);
    store.save(&state).unwrap();
    git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
    git(target.path(), &["commit", "-qm", "publish scoped replay"]);
    accept_review(target.path());
    let terminal = next(target.path()).await;
    assert!(terminal.terminal_allowed, "{terminal:?}");
    assert!(!terminal.workflow.unwrap().require_comparison);
    let summary = terminal.api_inventory.unwrap();
    assert_eq!(summary.completed, 1);
    assert_eq!(summary.skipped, 1);
    let before = fingerprint::repository_fingerprint(target.path()).unwrap();
    let attempt_count = store.load().unwrap().unwrap().attempts.len();

    policy(target.path(), "only: [GET /b]\nrequire_comparison: true\n");
    assert_eq!(
        fingerprint::repository_fingerprint(target.path()).unwrap(),
        before
    );
    let status = super::status_rewrite(super::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(!status.terminal_allowed);
    let envelope = next(target.path()).await;
    assert!(
        matches!(
            envelope.action,
            super::RewriteAction::ComparisonRecordingRequired { .. }
        ),
        "{envelope:?}"
    );
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.api, "GET /b");
    assert!(state.e2e_current);
    assert_eq!(state.attempts.len(), attempt_count);
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Skipped);
}

#[tokio::test]
async fn scope_is_terminal_with_required_comparison_and_does_not_disable_global_checks() {
    let target = target();
    git(target.path(), &["switch", "-qc", "rewrite-feature"]);
    policy(target.path(), "skip: [GET /b]\n");
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = super::test_state();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();
    regression_scope::apply(target.path(), &mut state).unwrap();
    pass_api(target.path(), &mut state);
    assert_eq!(state.phase, RewritePhase::ComparisonRecordingRequired);
    // Model a successful Comparison transition; terminal admission still uses
    // actual Git publication and a real delivery quality receipt below.
    state.comparison_current = true;
    inventory::complete_current_and_advance(&mut state).unwrap();
    state.phase = RewritePhase::SliceComplete;
    write_progress(target.path(), &state);
    store.save(&state).unwrap();
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
    git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
    git(target.path(), &["commit", "-qm", "publish comparison"]);
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
    accept_review(target.path());
    assert!(next(target.path()).await.terminal_allowed);

    fs::write(target.path().join("implementation.rs"), "// changed code\n").unwrap();
    assert!(
        !super::status_rewrite(super::RewriteContext {
            target_root: target.path().into()
        })
        .unwrap()
        .terminal_allowed
    );
}

#[test]
fn failed_replay_cannot_complete_with_comparison_disabled() {
    let target = target();
    policy(target.path(), "require_comparison: false\n");
    let mut state = super::test_state();
    inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
    regression_scope::apply(target.path(), &mut state).unwrap();
    let mut failed = result(&state);
    failed.passed = false;
    failed.gates.responses = crate::E2eResponseGate::Nonpassing;
    transition::from_e2e_result(
        target.path(),
        &mut state,
        &failed,
        AttemptTransition::Append,
    )
    .unwrap();
    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert!(!transition::complete_replay_if_ready(target.path(), &mut state).unwrap());
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
}

#[test]
fn revalidation_does_not_discard_a_newly_reclassified_replay_result() {
    let target = target();
    policy(target.path(), "require_comparison: false\n");
    let mut state = super::test_state();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();
    regression_scope::apply(target.path(), &mut state).unwrap();
    pass_api(target.path(), &mut state);
    fs::write(target.path().join("implementation.rs"), "// shared fix\n").unwrap();
    let observed = result(&state);
    transition::from_e2e_result(
        target.path(),
        &mut state,
        &observed,
        AttemptTransition::Append,
    )
    .unwrap();
    let current = fingerprint::repository_fingerprint(target.path()).unwrap();
    inventory::defer_completed_for_target_change(&mut state, &current).unwrap();
    assert_eq!(state.api, "GET /b");
    assert!(transition::complete_replay_if_ready(target.path(), &mut state).unwrap());
    assert_eq!(state.api_inventory[1].status, RewriteApiStatus::Complete);
    assert_eq!(state.api, "GET /a");
}

fn accept_review(root: &Path) {
    let report = super::review::check(super::review::RewriteReviewOptions {
        target_root: root.into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(report.status, super::review::ReviewStatus::Passed);
    super::review::accept(root.into(), report.report_path).unwrap();
}

fn pass_api(target: &Path, state: &mut RewriteState) {
    transition::from_e2e_result(target, state, &result(state), AttemptTransition::Append).unwrap();
    transition::complete_replay_if_ready(target, state).unwrap();
}

fn result(state: &RewriteState) -> crate::E2eApiRunResult {
    crate::E2eApiRunResult {
        run_key: state.recording_run_id.clone(),
        api: state.api.clone(),
        attempt: 1,
        status: "successful".into(),
        passed: true,
        gates: crate::E2eVerificationGates {
            responses: crate::E2eResponseGate::Passed,
            replay: crate::E2eReplayGate::Complete,
            dependencies: crate::E2eDependencyGate::Clean,
        },
        diagnosis: crate::E2eDiagnosis {
            egress_rejections: None,
            counts: crate::E2eDiagnosisCounts {
                selected: 1,
                executed: 1,
                response_passed: 1,
                response_nonpassing: 0,
                response_incomplete: 0,
            },
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
        progress: ".traffic-e2e/progress.yaml".into(),
        runtime_outputs: Vec::new(),
    }
}

fn write_progress(target: &Path, state: &RewriteState) {
    use crate::verification_progress::*;
    let path = target.join(".traffic-e2e/progress.yaml");
    let apis = state
        .api_inventory
        .iter()
        .filter(|item| item.status == RewriteApiStatus::Complete)
        .map(|item| {
            (
                item.api.clone(),
                ApiObservation {
                    cases: LatestCounts {
                        executed: 1,
                        passed: 1,
                    },
                    finalized: true,
                    passed: true,
                    success_streak: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut progress = ProgressReport::new(VerificationStage::Progress);
    progress
        .apply(ProgressObservation {
            key: state.recording_run_id.clone(),
            evidence_fingerprint: "replay-evidence".into(),
            finished_at: "2026-09-06T00:00:00Z".into(),
            finalized: true,
            passed: Some(true),
            success_streak: None,
            apis,
        })
        .unwrap();
    write(&path, &progress).unwrap();
}

fn target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    super::test_support::install_project_config(
        target.path(),
        "master",
        super::test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        target.path().join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(
        target.path().join(".gitignore"),
        "/.traffic-e2e/local/\n/.traffic-e2e/regression.yaml\n",
    )
    .unwrap();
    git(target.path(), &["init", "-q", "--initial-branch=master"]);
    git(target.path(), &["config", "user.name", "Test"]);
    git(target.path(), &["config", "user.email", "test@example.com"]);
    git(target.path(), &["add", "."]);
    git(target.path(), &["commit", "-qm", "baseline"]);
    git(target.path(), &["switch", "-qc", "fixture-work"]);
    target
}

fn git(target: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn next(target: &Path) -> super::RewriteActionEnvelope {
    super::next_rewrite(super::RewriteNextOptions {
        target_root: target.to_path_buf(),
        api: None,
        process_output: None,
        source_route: None,
    })
    .await
    .unwrap()
}
