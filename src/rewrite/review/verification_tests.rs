//! Receipt requirements persist across later recording and verification phases.
use super::*;
use crate::rewrite::model::RewriteApiStatus;
use crate::rewrite::{
    RewriteContext, RewriteNextOptions, RewriteProcessOutputProgress, RewriteProcessOutputStatus,
    artifacts, recording_action, recording_execution, traffic_operation,
};

fn target(phase: RewritePhase) -> (tempfile::TempDir, RewriteState) {
    let root = crate::rewrite::worker::tests::configured_target();
    source_diff::git_text(root.path(), &["switch", "-qc", "coordinator"]).unwrap();
    let mut state = crate::rewrite::test_state();
    crate::rewrite::inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    state.phase = phase;
    state.delivery_review_required = true;
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(root.path()).unwrap());
    if phase == RewritePhase::ComparisonRecordingRequired {
        state.comparison_run_id = Some("20260909010000".into());
    }
    RewriteStore::new(root.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (root, state)
}

fn comparison_manifest(root: &Path, state: &RewriteState, ready: bool) {
    let path = artifacts::comparison_manifest(root, state.comparison_run_id.as_ref().unwrap());
    write_json(
        &path,
        &serde_json::json!({
            "status": "completed", "ready": ready, "recording_apis": [state.api],
            "counts": {"published": 1, "failed": 0}, "errors": []
        }),
    )
    .unwrap();
}

fn next_options(root: &Path) -> RewriteNextOptions {
    RewriteNextOptions {
        target_root: root.into(),
        api: None,
        process_output: None,
        source_route: None,
    }
}

#[tokio::test]
async fn finalized_comparison_requires_a_receipt_before_entering_verification() {
    let (root, state) = target(RewritePhase::ComparisonRecordingRequired);
    comparison_manifest(root.path(), &state, true);
    let status = crate::rewrite::status_rewrite(RewriteContext {
        target_root: root.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        RewriteAction::SourceReviewRequired { .. }
    ));

    let result = crate::rewrite::next_rewrite(next_options(root.path()))
        .await
        .unwrap();

    assert!(matches!(
        result.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    let saved = RewriteStore::new(root.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(saved.phase, RewritePhase::ComparisonRecordingRequired);
    assert_eq!(saved.comparison_run_id, state.comparison_run_id);
    assert!(saved.attempts.is_empty());
    assert!(matches!(
        traffic_operation::state(root.path()).unwrap(),
        traffic_operation::TrafficOperationState::Absent
    ));
}

#[test]
fn review_admission_does_not_block_comparison_recording_or_its_recovery() {
    let (root, state) = target(RewritePhase::ComparisonRecordingRequired);
    assert!(required_action(root.path(), &state).unwrap().is_none());
    comparison_manifest(root.path(), &state, false);
    assert!(required_action(root.path(), &state).unwrap().is_none());
    comparison_manifest(root.path(), &state, true);
    let action_id = recording_action::recording_action_id(&state, true);
    recording_execution::publish(
        root.path(),
        &recording_execution::RecordingExecutionMarker {
            action_id: action_id.clone(),
            run_id: state.comparison_run_id.clone().unwrap(),
            operation: "record-comparison".into(),
            pid: std::process::id(),
        },
    )
    .unwrap();
    assert!(required_action(root.path(), &state).unwrap().is_none());
    recording_execution::clear(root.path(), &action_id).unwrap();
    assert!(matches!(
        required_action(root.path(), &state).unwrap(),
        Some(RewriteAction::SourceReviewRequired { .. })
    ));

    let mut initial = state;
    initial.delivery_review_required = false;
    assert!(required_action(root.path(), &initial).unwrap().is_none());
}

#[tokio::test]
async fn finalized_new_recording_installs_inventory_but_cannot_replay_without_receipt() {
    let (root, state) = target(RewritePhase::RecordingRequired);
    write_json(&artifacts::recording_manifest(root.path(), &state.recording_run_id),
        &serde_json::json!({"status": "completed", "recording_apis": [state.api], "published_cases": 1}))
        .unwrap();
    let case =
        artifacts::recording_run(root.path(), &state.recording_run_id).join("apis/get-api/case-1");
    fs::create_dir_all(&case).unwrap();
    write_json(
        &case.join("request.json"),
        &serde_json::json!({
            "method": "GET", "uri": "/api", "matched_rule": "http-rule", "api_pattern": "/api"
        }),
    )
    .unwrap();
    fs::write(case.join("expected-response.json"), "{}\n").unwrap();
    artifacts::validate_standard_recording(root.path(), &state).unwrap();
    assert_eq!(
        artifacts::standard_recording_apis(root.path(), &state).unwrap(),
        ["GET /api"]
    );
    assert!(matches!(
        crate::rewrite::status_rewrite(RewriteContext {
            target_root: root.path().into()
        })
        .unwrap()
        .action,
        RewriteAction::AdvanceRequired { .. }
    ));

    let result = crate::rewrite::next_rewrite(next_options(root.path()))
        .await
        .unwrap();

    assert!(
        matches!(result.action, RewriteAction::SourceReviewRequired { .. }),
        "unexpected verification action: {:?}",
        result.action
    );
    let saved = RewriteStore::new(root.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(saved.phase, RewritePhase::ApiPending);
    assert_eq!(saved.api_inventory.len(), 1);
    assert!(saved.delivery_review_required);
    assert!(saved.case_source.is_none());
    assert!(saved.attempts.is_empty());
    assert!(matches!(
        crate::rewrite::status_rewrite(RewriteContext {
            target_root: root.path().into()
        })
        .unwrap()
        .action,
        RewriteAction::SourceReviewRequired { .. }
    ));
}

#[test]
fn pending_and_revalidation_process_outputs_keep_the_receipt_gate_without_worker_binding() {
    for status in [
        RewriteProcessOutputStatus::Pending,
        RewriteProcessOutputStatus::RevalidationPending,
    ] {
        let (root, mut state) = target(RewritePhase::SliceComplete);
        state.api_inventory[0].status = RewriteApiStatus::Complete;
        state
            .process_outputs
            .inventory
            .push(RewriteProcessOutputProgress {
                id: "profile".into(),
                status,
                attempts: 0,
                verified_target_fingerprint: None,
                issue: None,
            });
        assert!(state.worker_bindings.is_empty());
        assert!(matches!(
            required_action(root.path(), &state).unwrap(),
            Some(RewriteAction::SourceReviewRequired { .. })
        ));
        state.delivery_review_required = false;
        assert!(required_action(root.path(), &state).unwrap().is_none());
    }
}
