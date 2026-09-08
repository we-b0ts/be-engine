use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::model::{RewriteApiStatus, RewritePhase, RewriteRecordingReason, RewriteState};
use super::store::RewriteStore;
use super::transition::{self, AttemptTransition};
use super::{action, fingerprint, inventory, progress_publication, recording};

#[tokio::test]
async fn first_terminal_persists_latch_without_changing_batch_and_next_batch_requires_comparison() {
    let target = target();
    git(target.path(), &["switch", "-qc", "rewrite-feature"]);
    let initial = next(target.path()).await;
    assert!(!initial.workflow.unwrap().require_comparison);
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    assert!(!state.require_comparison);
    let first_run = state.recording_run_id.clone();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();

    pass_api(target.path(), &mut state);
    assert_eq!(state.api, "GET /b");
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
    assert!(!state.api_inventory[0].comparison_current);
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
    store.save(&state).unwrap();
    state = store.load().unwrap().unwrap();
    assert!(!state.recording_require_comparison);

    pass_api(target.path(), &mut state);
    assert_eq!(state.phase, RewritePhase::SliceComplete);
    write_progress(target.path(), &state);
    store.save(&state).unwrap();
    super::review::check(super::review::RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
    })
    .unwrap();
    let awaiting_commit = next(target.path()).await;
    assert!(!awaiting_commit.terminal_allowed);
    assert!(!store.load().unwrap().unwrap().require_comparison);
    git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
    git(target.path(), &["commit", "-qm", "publish first batch"]);

    let status = super::status_rewrite(super::RewriteContext {
        target_root: target.path().to_path_buf(),
    })
    .unwrap();
    assert!(!status.terminal_allowed);
    assert!(matches!(
        status.action,
        super::model::RewriteAction::AdvanceRequired { .. }
    ));
    assert!(!store.load().unwrap().unwrap().require_comparison);
    let completed = next(target.path()).await;
    assert!(completed.terminal_allowed);
    let view = completed.workflow.unwrap();
    assert!(!view.require_comparison);
    assert!(view.next_recording_require_comparison);
    state = store.load().unwrap().unwrap();
    assert!(state.require_comparison);
    assert!(!state.recording_require_comparison);
    assert_eq!(state.recording_run_id, first_run);
    let revision = state.revision;
    super::recover_rewrite(super::RewriteContext {
        target_root: target.path().to_path_buf(),
    })
    .await
    .unwrap();
    assert!(next(target.path()).await.terminal_allowed);
    assert_eq!(store.load().unwrap().unwrap().revision, revision);
    assert!(
        super::status_rewrite(super::RewriteContext {
            target_root: target.path().to_path_buf(),
        })
        .unwrap()
        .terminal_allowed
    );

    let requested =
        recording::request_rewrite_recording(recording::RewriteRecordingRequestOptions {
            target_root: target.path().to_path_buf(),
            kind: super::model::RewriteRecordingKind::Standard,
            reason: RewriteRecordingReason::SourceBaselineChanged,
            duration_seconds: state.recording_settings.duration_seconds,
            per_api_case_limit: state.recording_settings.per_api_case_limit,
            api: None,
            replace_pending: false,
        })
        .unwrap();
    assert!(requested.workflow.unwrap().require_comparison);
    state = store.load().unwrap().unwrap();
    assert_ne!(state.recording_run_id, first_run);
    assert!(state.recording_require_comparison);
    inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
    pass_api(target.path(), &mut state);
    assert_eq!(state.phase, RewritePhase::ComparisonRecordingRequired);
    assert!(state.comparison_run_id.is_some());
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
}

#[test]
fn failed_replay_and_unfinished_process_outputs_cannot_enable_comparison() {
    let target = target();
    let store = RewriteStore::new(target.path()).unwrap();
    let _lock = store.lock().unwrap();
    let mut state = first_batch();
    inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
    let mut result = result(&state);
    result.passed = false;
    result.gates.responses = crate::E2eResponseGate::Nonpassing;
    result.diagnosis.counts.response_passed = 0;
    result.diagnosis.counts.response_nonpassing = 1;
    transition::from_e2e_result(
        target.path(),
        &mut state,
        &result,
        AttemptTransition::Append,
    )
    .unwrap();
    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert!(!transition::complete_replay_if_ready(target.path(), &mut state).unwrap());
    progress_publication::finalize_if_published(target.path(), &store, &mut state).unwrap();
    assert!(!state.require_comparison);

    pass_api(target.path(), &mut state);
    write_progress(target.path(), &state);
    git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
    git(target.path(), &["commit", "-qm", "publish replay"]);
    state.process_outputs.inventory.push(
        super::process_output_model::RewriteProcessOutputProgress {
            id: "metrics".into(),
            status: super::process_output_model::RewriteProcessOutputStatus::Pending,
            attempts: 0,
            verified_target_fingerprint: None,
            issue: None,
        },
    );
    progress_publication::finalize_if_published(target.path(), &store, &mut state).unwrap();
    assert!(!state.require_comparison);
    assert!(!action::for_state(target.path(), &state).terminal_allowed);
}

#[test]
fn stale_target_cannot_finalize_first_batch() {
    let target = target();
    let store = RewriteStore::new(target.path()).unwrap();
    let _lock = store.lock().unwrap();
    let mut state = first_batch();
    inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
    pass_api(target.path(), &mut state);
    write_progress(target.path(), &state);
    git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
    git(target.path(), &["commit", "-qm", "publish replay"]);
    fs::write(
        target.path().join("implementation.rs"),
        "// changed target\n",
    )
    .unwrap();
    progress_publication::finalize_if_published(target.path(), &store, &mut state).unwrap();
    assert!(!state.require_comparison);
    let current = fingerprint::repository_fingerprint(target.path()).unwrap();
    assert!(inventory::defer_completed_for_target_change(&mut state, &current).unwrap());
    assert_eq!(state.phase, RewritePhase::ApiPending);
    assert!(!state.recording_require_comparison);
    pass_api(target.path(), &mut state);
    assert_eq!(state.phase, RewritePhase::SliceComplete);
}

#[test]
fn parked_reclassification_defers_scheduling_until_coordinator_activation() {
    let target = target();
    let mut state = first_batch();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();
    let mut prior = result(&state);
    prior.passed = false;
    prior.gates.dependencies = crate::E2eDependencyGate::Dirty;
    transition::from_e2e_result(target.path(), &mut state, &prior, AttemptTransition::Append)
        .unwrap();
    super::worker::confirm_current_for_test(&mut state);
    inventory::activate_requested(&mut state, Some(&"GET /b".parse().unwrap())).unwrap();
    inventory::with_slice_mut(&mut state, "GET /a", |state| {
        transition::from_e2e_result(
            target.path(),
            state,
            &result(state),
            AttemptTransition::ReclassifyCurrent,
        )
    })
    .unwrap();
    assert_eq!(state.api, "GET /b");
    assert_eq!(state.current_api_index, Some(1));
    assert_eq!(state.parked_slices["GET /a"].api, "GET /a");
    assert_eq!(
        state.parked_slices["GET /a"].phase,
        RewritePhase::SliceComplete
    );
    inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).unwrap();
    assert!(transition::complete_replay_if_ready(target.path(), &mut state).unwrap());
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
    assert_eq!(state.api, "GET /b");
}

#[test]
fn absent_flags_default_false_and_batch_snapshot_survives_serialization_and_refresh() {
    let mut value = serde_json::to_value(super::test_state()).unwrap();
    value.as_object_mut().unwrap().remove("require_comparison");
    value
        .as_object_mut()
        .unwrap()
        .remove("recording_require_comparison");
    let legacy: RewriteState = serde_json::from_value(value).unwrap();
    assert!(!legacy.require_comparison);
    assert!(!legacy.recording_require_comparison);

    let mut state = first_batch();
    let settings = state.recording_settings;
    recording::reset_for_fresh_recording(
        &mut state,
        "retry".into(),
        settings,
        RewriteRecordingReason::RecorderContractChanged,
    );
    assert!(!state.recording_require_comparison);
    state.require_comparison = true;
    let mut restored: RewriteState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(!restored.recording_require_comparison);
    recording::reset_for_fresh_recording(
        &mut restored,
        "next".into(),
        settings,
        RewriteRecordingReason::SourceBaselineChanged,
    );
    assert!(restored.recording_require_comparison);
}

#[test]
fn revalidation_does_not_discard_a_newly_reclassified_replay_result() {
    let target = target();
    let mut state = first_batch();
    inventory::install(&mut state, vec!["GET /a".into(), "GET /b".into()]).unwrap();
    pass_api(target.path(), &mut state);
    assert_eq!(state.api, "GET /b");
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
    assert!(state.e2e_current);
    assert!(transition::complete_replay_if_ready(target.path(), &mut state).unwrap());
    assert_eq!(state.api_inventory[1].status, RewriteApiStatus::Complete);
    assert_eq!(state.api, "GET /a");
    assert_eq!(state.phase, RewritePhase::ApiPending);
}

#[tokio::test]
async fn legacy_pending_comparison_uses_missing_batch_default_without_recording_comparison() {
    let target = target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = super::test_state();
    inventory::install(&mut state, vec!["GET /a".into()]).unwrap();
    pass_api(target.path(), &mut state);
    assert_eq!(state.phase, RewritePhase::ComparisonRecordingRequired);
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy.as_object_mut().unwrap().remove("require_comparison");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("recording_require_comparison");
    state = serde_json::from_value(legacy).unwrap();
    store.save(&state).unwrap();
    let action = action::for_status(target.path(), &state).unwrap();
    assert!(matches!(
        action.action,
        super::model::RewriteAction::AdvanceRequired { .. }
    ));
    next(target.path()).await;
    let restored = store.load().unwrap().unwrap();
    assert_eq!(restored.phase, RewritePhase::SliceComplete);
    assert_eq!(restored.api_inventory[0].status, RewriteApiStatus::Complete);
    assert!(restored.e2e_current);
    assert!(!restored.comparison_current);
    assert!(restored.comparison_run_id.is_none());
}

fn first_batch() -> RewriteState {
    let mut state = super::test_state();
    state.require_comparison = false;
    state.recording_require_comparison = false;
    state.recording_apis.clear();
    state
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
    fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    git(target.path(), &["init", "-q", "--initial-branch=master"]);
    git(target.path(), &["config", "user.name", "Test"]);
    git(target.path(), &["config", "user.email", "test@example.com"]);
    git(target.path(), &["add", "."]);
    git(target.path(), &["commit", "-qm", "baseline"]);
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
