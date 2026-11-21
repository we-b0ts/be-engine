//! Receipt requirements persist across later recording and verification phases.
use super::*;
use crate::model::RewritePhase;
use crate::{RewriteContext, artifacts};

fn target(phase: RewritePhase) -> (tempfile::TempDir, RewriteState) {
    let root = crate::worker::tests::configured_target();
    source_diff::git_text(root.path(), &["switch", "-qc", "coordinator"]).unwrap();
    let mut state = crate::test_state();
    crate::inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    state.phase = phase;
    state.delivery_review_required = true;
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(root.path()).unwrap());
    RewriteStore::new(root.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (root, state)
}

#[test]
fn finalized_new_recording_does_not_require_an_ordinary_review_receipt() {
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
        crate::status_rewrite(RewriteContext {
            target_root: root.path().into()
        })
        .unwrap()
        .action,
        RewriteAction::AdvanceRequired { .. }
    ));

    assert!(gate(root.path(), &state, "master").unwrap().is_none());
    assert!(required_action(root.path(), &state).unwrap().is_none());
}
