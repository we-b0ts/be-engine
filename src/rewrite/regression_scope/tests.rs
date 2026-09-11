use super::*;
use crate::rewrite::{scheduling, store::RewriteStore, test_support, worker};

fn target() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".traffic-e2e")).unwrap();
    root
}

fn write(root: &Path, policy: &str) {
    std::fs::write(root.join(PATH), policy).unwrap();
}

fn state() -> RewriteState {
    let mut state = test_support::test_state();
    inventory::install(
        &mut state,
        vec!["GET /a".into(), "GET /b".into(), "GET /c/*".into()],
    )
    .unwrap();
    state
}

#[test]
fn only_and_skip_intersect_and_deleting_policy_restores_original_work() {
    let root = target();
    let mut state = state();
    write(root.path(), "only: [GET /a, GET /b]\nskip: [GET /a]\n");
    apply(root.path(), &mut state).unwrap();
    assert_eq!(state.api, "GET /b");
    assert_eq!(inventory::view(&state).skipped, 2);
    assert_eq!(inventory::view(&state).completed, 0);
    assert_eq!(
        state.parked_slices["GET /a"].phase,
        RewritePhase::ApiPending
    );
    let store = RewriteStore::new(root.path()).unwrap();
    store.save(&state).unwrap();
    assert!(!apply(root.path(), &mut state).unwrap());
    std::fs::remove_file(root.path().join(PATH)).unwrap();
    let state = store.load().unwrap().unwrap();
    assert_eq!(inventory::view(&state).skipped, 0);
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Pending);
    assert_eq!(state.api_inventory[2].status, RewriteApiStatus::Pending);
    assert!(state.skipped_api_statuses.is_empty());
}

#[test]
fn excluded_worker_and_system_repair_do_not_reenter_scheduler() {
    let root = target();
    let mut state = state();
    state.phase = RewritePhase::SystemRepairRequired;
    write(root.path(), "skip: [GET /a]\n");
    apply(root.path(), &mut state).unwrap();
    assert!(scheduling::repair_apis(&state).is_empty());
    assert!(worker::runtime::scopes(&state).is_empty());
    assert_eq!(
        state.parked_slices["GET /a"].phase,
        RewritePhase::SystemRepairRequired
    );
    std::fs::remove_file(root.path().join(PATH)).unwrap();
    apply(root.path(), &mut state).unwrap();
    assert_eq!(scheduling::repair_apis(&state), vec!["GET /a"]);
}

#[test]
fn skip_all_keeps_history_and_explicit_api_is_complete_without_fake_evidence() {
    let root = target();
    let mut state = state();
    write(root.path(), "skip: [GET /a, GET /b, GET /c/*]\n");
    apply(root.path(), &mut state).unwrap();
    assert_eq!(state.phase, RewritePhase::SliceComplete);
    assert_eq!(state.current_api_index, None);
    assert!(!state.e2e_current);
    assert_eq!(inventory::view(&state).skipped, 3);
    let envelope = skipped_envelope(root.path(), &state, "GET /a").unwrap();
    assert!(matches!(
        envelope.action,
        RewriteAction::Complete {
            e2e_current: false,
            comparison_current: false,
            ..
        }
    ));
    assert!(envelope.latest_focused_e2e.is_none());
}

#[test]
fn omitted_null_and_empty_only_restore_all_apis_and_still_apply_skip() {
    let root = target();
    for policy in ["", "only:\n", "only: null\n", "only: []\n"] {
        let mut state = state();
        write(root.path(), "only: [GET /a]\n");
        apply(root.path(), &mut state).unwrap();
        assert_eq!(inventory::view(&state).skipped, 2);

        write(root.path(), &format!("{policy}skip: []\n"));
        apply(root.path(), &mut state).unwrap();
        assert_eq!(inventory::view(&state).skipped, 0, "{policy}");
        assert!(
            state
                .api_inventory
                .iter()
                .all(|item| !item.status.is_done())
        );

        write(root.path(), &format!("{policy}skip: [GET /a]\n"));
        apply(root.path(), &mut state).unwrap();
        assert_eq!(inventory::view(&state).skipped, 1, "{policy}");
        assert!(is_skipped(&state, "GET /a"));
        assert_eq!(state.api, "GET /b");
        assert!(!is_skipped(&state, "GET /c/*"));
    }
}

#[test]
fn invalid_policy_fails_without_changing_progress() {
    let root = target();
    let mut state = state();
    let original = serde_json::to_value(&state).unwrap();
    for policy in [
        "only: [GET /typo]",
        "skip: [GET /a, GET /a]",
        "skip: [not-an-api]",
        "onyl: [GET /a]",
        "require_comparison: perhaps",
    ] {
        write(root.path(), policy);
        assert!(apply(root.path(), &mut state).is_err(), "{policy}");
        assert_eq!(serde_json::to_value(&state).unwrap(), original);
    }
}

#[test]
fn config_changes_wait_for_the_active_traffic_operation() {
    let root = target();
    let mut state = state();
    use crate::rewrite::traffic_operation::{
        TrafficOperationClaim, TrafficOperationKind, claim_current,
    };
    let claim = claim_current(
        root.path(),
        "test".into(),
        TrafficOperationKind::Replay,
        Some(state.api.clone()),
    )
    .unwrap();
    let TrafficOperationClaim::Acquired(guard) = claim else {
        panic!("expected claim")
    };
    write(root.path(), "skip: [GET /a]\nrequire_comparison: false\n");
    assert!(!apply(root.path(), &mut state).unwrap());
    assert_eq!(state.api, "GET /a");
    assert!(state.require_comparison);
    drop(guard);
    apply(root.path(), &mut state).unwrap();
    assert_eq!(state.api, "GET /b");
    assert!(!state.require_comparison);
}
