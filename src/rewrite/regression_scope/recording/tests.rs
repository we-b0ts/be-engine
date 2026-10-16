use std::{fs, path::Path, process::Command};

use super::*;
use crate::rewrite::{
    self, RewriteAction, RewriteContext, RewriteNextOptions, store::RewriteStore, test_support,
};

const A: &str = "20260911093000";
const B: &str = "20260911094000";

fn target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    test_support::install_project_config(
        target.path(),
        "master",
        test_support::managed_test_recorder(),
        None,
    );
    let mut source_policy = crate::config::SourceTrafficPolicyConfig::empty();
    source_policy.http.source_revision = format!("sha256:{}", "1".repeat(64));
    source_policy.http.case_path_patterns = vec!["/users/*".into(), "/orders/*".into()];
    fs::write(
        target.path().join(".traffic-e2e/policy.yaml"),
        source_policy.render().unwrap(),
    )
    .unwrap();
    fs::write(
        target.path().join(".gitignore"),
        "/.traffic-e2e/local/\n/.traffic-e2e/regression.yaml\n",
    )
    .unwrap();
    for args in [
        vec!["init", "-q", "--initial-branch=master"],
        vec!["config", "user.name", "Test"],
        vec!["config", "user.email", "test@example.com"],
        vec!["add", "."],
        vec!["commit", "-qm", "baseline"],
        vec!["switch", "-qc", "fixture-work"],
    ] {
        let output = Command::new("git")
            .arg("-C")
            .arg(target.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    target
}

fn record(root: &Path, id: &str, scope: &[&str], paths: &[&str], status: &str) {
    let run = artifacts::recording_run(root, id);
    fs::create_dir_all(&run).unwrap();
    for (index, path) in paths.iter().enumerate() {
        let case = run.join("apis/cases").join(format!("case-{index}"));
        fs::create_dir_all(&case).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::to_vec(&serde_json::json!({"method": "GET", "uri": path})).unwrap(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}\n").unwrap();
    }
    fs::write(
        run.join("recording-run.json"),
        serde_json::to_vec(&serde_json::json!({
            "status": status, "recording_apis": scope, "published_cases": paths.len()
        }))
        .unwrap(),
    )
    .unwrap();
}

fn policy(root: &Path, id: &str, extra: &str) {
    fs::write(
        root.join(PATH),
        format!("recording_run_id: \"{id}\"\n{extra}"),
    )
    .unwrap();
}

fn pending_pattern_state(root: &Path) -> RewriteState {
    record(
        root,
        A,
        &[],
        &["/users/1", "/orders/2", "/new-static"],
        "completed",
    );
    policy(root, A, "only: [/users/*]\n");
    let mut state = test_support::test_state();
    super::super::apply(root, &mut state).unwrap();
    assert!(rewrite::case_patterns::identify_after_finalized_recording(root, &mut state).unwrap());
    assert!(state.api_inventory.is_empty());
    assert_eq!(state.phase, RewritePhase::RecordingRequired);
    state
}

#[test]
fn pinned_pattern_wait_reuses_observations_but_apply_still_validates_cases() {
    let root = target();
    let state = pending_pattern_state(root.path());
    let batch_id = state
        .case_pattern_identification
        .as_ref()
        .unwrap()
        .id
        .clone();
    let store = RewriteStore::new(root.path()).unwrap();
    store.save(&state).unwrap();
    let state_path = crate::internal_runtime::root(root.path()).join("rewrite/state.json");
    let state_before = fs::read(&state_path).unwrap();
    let policy_path = root.path().join(".traffic-e2e/policy.yaml");
    let policy_before = fs::read(&policy_path).unwrap();
    fs::write(
        artifacts::recording_run(root.path(), A).join("apis/cases/case-0/request.json"),
        "invalid request",
    )
    .unwrap();

    for _ in 0..2 {
        let status = rewrite::status_rewrite(RewriteContext {
            target_root: root.path().into(),
        })
        .unwrap();
        assert!(matches!(
            status.action,
            RewriteAction::CasePatternIdentificationRequired { .. }
        ));
    }
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    assert!(
        rewrite::case_patterns::apply(rewrite::RewriteCasePatternApplyOptions {
            target_root: root.path().into(),
            batch_id,
            patterns: vec![],
        })
        .is_err()
    );
    assert_eq!(fs::read(&state_path).unwrap(), state_before);
    assert_eq!(fs::read(&policy_path).unwrap(), policy_before);
}

#[test]
fn pinned_pattern_snapshot_rechecks_selectors_rules_manifest_and_recording_identity() {
    let root = target();
    let mut state = pending_pattern_state(root.path());
    let request = artifacts::recording_run(root.path(), A).join("apis/cases/case-0/request.json");
    fs::write(&request, "invalid request").unwrap();
    let original = serde_json::to_value(&state).unwrap();
    policy(root.path(), A, "only: [/absent]\n");
    assert!(super::super::apply(root.path(), &mut state).is_err());
    policy(root.path(), A, "only: [/users/*]\n");
    assert!(!super::super::apply(root.path(), &mut state).unwrap());
    let path = root.path().join(".traffic-e2e/policy.yaml");
    let original_policy = fs::read(&path).unwrap();
    let mut policy_document = crate::config::SourceTrafficPolicyConfig::empty();
    policy_document.http.source_revision = format!("sha256:{}", "1".repeat(64));
    policy_document.http.case_path_patterns = vec!["/orders/*".into()];
    fs::write(&path, policy_document.render().unwrap()).unwrap();
    assert!(super::super::apply(root.path(), &mut state).is_err());
    fs::write(&path, original_policy).unwrap();
    policy(root.path(), B, "");
    assert!(super::super::apply(root.path(), &mut state).is_err());
    assert_eq!(serde_json::to_value(&state).unwrap(), original);
    policy(root.path(), A, "");
    state
        .case_pattern_identification
        .as_mut()
        .unwrap()
        .recording_run_id = B.into();
    assert!(super::super::apply(root.path(), &mut state).is_err());
    state
        .case_pattern_identification
        .as_mut()
        .unwrap()
        .recording_run_id = A.into();
    fs::remove_file(artifacts::recording_manifest(root.path(), A)).unwrap();
    assert!(super::super::apply(root.path(), &mut state).is_err());
}

#[test]
fn pinned_pattern_snapshot_preserves_legacy_recorded_pattern_selectors() {
    let root = target();
    record(
        root.path(),
        A,
        &[],
        &["/legacy/1", "/new-static"],
        "completed",
    );
    fs::write(
        artifacts::recording_run(root.path(), A).join("apis/cases/case-0/request.json"),
        r#"{"method":"GET","uri":"/legacy/1","api_pattern":"/legacy/*"}"#,
    )
    .unwrap();
    policy(root.path(), A, "only: [/legacy/*]\n");
    let mut state = test_support::test_state();
    super::super::apply(root.path(), &mut state).unwrap();
    assert!(
        rewrite::case_patterns::identify_after_finalized_recording(root.path(), &mut state)
            .unwrap()
    );
    let original = serde_json::to_value(&state).unwrap();
    assert!(!super::super::apply(root.path(), &mut state).unwrap());
    assert_eq!(serde_json::to_value(&state).unwrap(), original);
}

async fn next(root: &Path) -> Result<rewrite::RewriteActionEnvelope> {
    rewrite::next_rewrite(RewriteNextOptions {
        target_root: root.into(),
        api: None,
        source_route: None,
    })
    .await
}

#[tokio::test]
async fn next_adopts_pinned_recording_and_filters_its_inventory_without_recapture() {
    let root = target();
    record(root.path(), A, &[], &["/users/1", "/orders/2"], "completed");
    policy(
        root.path(),
        A,
        "only: [/users/*, /orders/*]\nskip: [/orders/*]\n",
    );
    let manifest = artifacts::recording_manifest(root.path(), A);
    let original = fs::read(&manifest).unwrap();
    let action = next(root.path()).await.unwrap();
    assert!(!matches!(
        action.action,
        RewriteAction::InputRequired {
            reason: crate::rewrite::RewriteInputRequiredReason::RecordingEvidenceRequired,
            ..
        }
    ));
    let state = RewriteStore::new(root.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(state.recording_run_id, A);
    assert_eq!(state.api, "GET /users/*");
    assert_eq!(state.phase, RewritePhase::ApiPending);
    assert_eq!(inventory::view(&state).skipped, 1);
    assert!(state.recording_apis.is_empty());
    assert!(state.recording_input_case_source.is_none());
    assert!(state.recording_input_diagnosis.is_none());
    assert!(state.attempts.is_empty());
    assert_eq!(fs::read(&manifest).unwrap(), original);
    assert_eq!(
        fs::read_dir(manifest.parent().unwrap().parent().unwrap())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn pinned_recording_accepts_route_selectors_for_its_method_inventory() {
    let root = target();
    record(
        root.path(),
        A,
        &["GET /users/*", "PUT /users/*"],
        &["/users/1", "/users/2"],
        "completed",
    );
    fs::write(
        artifacts::recording_run(root.path(), A).join("apis/cases/case-1/request.json"),
        serde_json::to_vec(&serde_json::json!({"method": "PUT", "uri": "/users/2"})).unwrap(),
    )
    .unwrap();
    policy(root.path(), A, "only: [/users/*]\n");
    let manifest = artifacts::recording_manifest(root.path(), A);
    let original_manifest = fs::read(&manifest).unwrap();
    validate_uninitialized(root.path()).unwrap();
    let mut state = test_support::test_state();
    assert!(super::super::apply(root.path(), &mut state).unwrap());
    inventory::install(
        &mut state,
        vec!["GET /users/*".into(), "PUT /users/*".into()],
    )
    .unwrap();
    super::super::apply(root.path(), &mut state).unwrap();
    assert_eq!(inventory::view(&state).total, 1);
    assert_eq!(inventory::view(&state).skipped, 0);
    policy(root.path(), A, "skip: [/users/*]\n");
    super::super::apply(root.path(), &mut state).unwrap();
    assert!(
        state
            .api_inventory
            .iter()
            .all(|item| item.status == crate::rewrite::RewriteApiStatus::Skipped)
    );
    assert_eq!(fs::read(&manifest).unwrap(), original_manifest);
}

#[tokio::test]
async fn unavailable_pinned_recording_blocks_status_and_next_without_fallback() {
    let root = target();
    // A different usable run must never be chosen as fallback.
    record(
        root.path(),
        B,
        &["GET /users/*"],
        &["/users/1"],
        "completed",
    );
    policy(root.path(), A, "");
    for status in [
        "missing",
        "running",
        "failed",
        "empty",
        "corrupt",
        "missing_cases",
    ] {
        match status {
            "missing" => {}
            "empty" => record(root.path(), A, &[], &[], "completed"),
            "corrupt" => {
                fs::write(artifacts::recording_manifest(root.path(), A), "invalid").unwrap()
            }
            "missing_cases" => record(root.path(), A, &["GET /absent"], &["/users/1"], "completed"),
            status => record(root.path(), A, &[], &["/users/1"], status),
        }
        let context = RewriteContext {
            target_root: root.path().into(),
        };
        let error = rewrite::status_rewrite(context).unwrap_err();
        assert!(
            format!("{error:#}").contains("recording_run_id"),
            "{status}: {error:#}"
        );
        assert!(next(root.path()).await.is_err(), "{status}");
        assert!(
            !crate::internal_runtime::root(root.path())
                .join("rewrite/state.json")
                .exists()
        );
    }
}

#[test]
fn switching_recordings_resets_verification_and_clearing_pin_keeps_current_baseline() {
    let root = target();
    record(
        root.path(),
        A,
        &["GET /users/*"],
        &["/users/1"],
        "completed",
    );
    record(
        root.path(),
        B,
        &["GET /orders/*"],
        &["/orders/2"],
        "completed",
    );
    let store = RewriteStore::new(root.path()).unwrap();
    let mut state = test_support::test_state();
    for (id, api) in [
        (A, "GET /users/*"),
        (B, "GET /orders/*"),
        (A, "GET /users/*"),
    ] {
        policy(
            root.path(),
            id,
            &format!("only: [{}]\n", crate::recording_api::identity(api)),
        );
        assert!(super::super::apply(root.path(), &mut state).unwrap());
        assert_eq!(state.recording_run_id, id);
        assert_eq!(state.recording_apis, vec![api]);
        assert!(state.api_inventory.is_empty());
        assert!(state.parked_slices.is_empty());
        assert!(!state.e2e_current);
        assert!(state.case_source.is_none() && state.target_fingerprint.is_none());
        inventory::install(&mut state, vec![api.into()]).unwrap();
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = true;
        state.case_source = Some(artifacts::recording_run(root.path(), id));
        state.target_fingerprint = Some("old-target".into());
        inventory::complete_current_and_advance(&mut state).unwrap();
        store.save(&state).unwrap();
    }
    assert!(ensure_fresh_allowed(root.path(), &crate::rewrite::test_state()).is_err());
    fs::remove_file(root.path().join(PATH)).unwrap();
    ensure_fresh_allowed(root.path(), &crate::rewrite::test_state()).unwrap();
    let reloaded = store.load().unwrap().unwrap();
    assert_eq!(reloaded.recording_run_id, A);
    assert_eq!(reloaded.phase, RewritePhase::SliceComplete);
    policy(root.path(), "", "");
    ensure_fresh_allowed(root.path(), &crate::rewrite::test_state()).unwrap();
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        serde_json::to_value(&reloaded).unwrap()
    );
    policy(root.path(), A, "");
    fs::remove_dir_all(artifacts::recording_run(root.path(), A)).unwrap();
    assert!(store.load().is_err());
}

#[test]
fn pinned_recording_change_waits_for_running_traffic() {
    use crate::rewrite::traffic_operation::{
        TrafficOperationClaim, TrafficOperationKind, claim_current,
    };
    let root = target();
    record(
        root.path(),
        A,
        &["GET /users/*"],
        &["/users/1"],
        "completed",
    );
    let mut state = test_support::test_state();
    let original = serde_json::to_value(&state).unwrap();
    let TrafficOperationClaim::Acquired(guard) = claim_current(
        root.path(),
        "test".into(),
        TrafficOperationKind::Replay,
        Some(state.api.clone()),
    )
    .unwrap() else {
        panic!("expected traffic claim");
    };
    policy(root.path(), A, "");
    assert!(!super::super::apply(root.path(), &mut state).unwrap());
    assert_eq!(serde_json::to_value(&state).unwrap(), original);
    drop(guard);
    assert!(super::super::apply(root.path(), &mut state).unwrap());
    assert_eq!(state.recording_run_id, A);
}

#[tokio::test]
async fn status_and_next_switch_between_existing_recordings_and_clear_passes() {
    let root = target();
    record(
        root.path(),
        A,
        &["GET /users/*"],
        &["/users/1"],
        "completed",
    );
    record(
        root.path(),
        B,
        &["GET /orders/*"],
        &["/orders/2"],
        "completed",
    );
    let store = RewriteStore::new(root.path()).unwrap();
    for (id, api) in [
        (A, "GET /users/*"),
        (B, "GET /orders/*"),
        (A, "GET /users/*"),
    ] {
        policy(
            root.path(),
            id,
            &format!("only: [{}]\n", crate::recording_api::identity(api)),
        );
        let status = rewrite::status_rewrite(RewriteContext {
            target_root: root.path().into(),
        })
        .unwrap();
        assert!(!status.terminal_allowed);
        next(root.path()).await.unwrap();
        let mut state = store.load().unwrap().unwrap();
        assert_eq!(state.recording_run_id, id);
        assert_eq!(state.api, api);
        assert!(!state.e2e_current);
        assert_eq!(state.phase, RewritePhase::ApiPending);
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = true;
        state.target_fingerprint =
            Some(rewrite::fingerprint::repository_fingerprint(root.path()).unwrap());
        inventory::complete_current_and_advance(&mut state).unwrap();
        store.save(&state).unwrap();
    }
}

#[test]
fn invalid_run_ids_and_new_inventory_selectors_do_not_mutate_state() {
    let root = target();
    record(
        root.path(),
        A,
        &["GET /users/*"],
        &["/users/1"],
        "completed",
    );
    let mut state = test_support::test_state();
    let original = serde_json::to_value(&state).unwrap();
    for id in [
        " ",
        "../20260911093000",
        "2026091109300x",
        "202609110930000",
    ] {
        policy(root.path(), id, "");
        assert!(super::super::apply(root.path(), &mut state).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), original);
    }
    policy(root.path(), A, "only: [/typo]\n");
    assert!(super::super::apply(root.path(), &mut state).is_err());
    assert_eq!(serde_json::to_value(&state).unwrap(), original);
}

#[tokio::test]
async fn omitted_null_and_empty_recording_ids_wait_for_external_evidence() {
    for config in [
        "only: []\n",
        "recording_run_id:\n",
        "recording_run_id: null\n",
        "recording_run_id: \"\"\n",
    ] {
        let root = target();
        fs::write(root.path().join(PATH), config).unwrap();
        ensure_fresh_allowed(root.path(), &crate::rewrite::test_state()).unwrap();
        let status = rewrite::status_rewrite(RewriteContext {
            target_root: root.path().into(),
        })
        .unwrap();
        assert!(!status.initialized);
        let action = next(root.path()).await.unwrap();
        assert!(matches!(
            action.action,
            RewriteAction::InputRequired {
                reason: crate::rewrite::RewriteInputRequiredReason::RecordingEvidenceRequired,
                ..
            }
        ));
        let state = RewriteStore::new(root.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.phase, RewritePhase::RecordingRequired);
        assert!(state.recording_run_id.is_empty());
    }
}
