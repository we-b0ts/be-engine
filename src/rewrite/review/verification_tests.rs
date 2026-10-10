//! Receipt requirements persist across later recording and verification phases.
use super::*;
use crate::rewrite::{RewriteContext, RewriteNextOptions, artifacts};

fn target(phase: RewritePhase) -> (tempfile::TempDir, RewriteState) {
    let root = crate::rewrite::worker::tests::configured_target();
    source_diff::git_text(root.path(), &["switch", "-qc", "coordinator"]).unwrap();
    let mut state = crate::rewrite::test_state();
    crate::rewrite::inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    state.phase = phase;
    state.delivery_review_required = true;
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(root.path()).unwrap());
    RewriteStore::new(root.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (root, state)
}

fn next_options(root: &Path) -> RewriteNextOptions {
    RewriteNextOptions {
        target_root: root.into(),
        api: None,
        source_route: None,
    }
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
