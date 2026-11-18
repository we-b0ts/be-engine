use super::*;
use crate::{
    inventory,
    model::{RewriteApiStatus, RewriteRecordingReason, RewriteRecordingSettings},
    recording::reset_for_fresh_recording,
    store::RewriteStore,
    workflow_test_support,
};

const API: &str = "GET /api/tasks/*";
const ROUTE: &str = "/api/tasks/{task_id}";
const SECOND_API: &str = "GET /api/users/*";
const SECOND_ROUTE: &str = "/api/users/{user_id}";

fn legacy_state() -> RewriteState {
    let mut state = workflow_test_support::test_state();
    state.recording_apis.clear();
    inventory::install(&mut state, vec![API.into(), SECOND_API.into()]).unwrap();
    bind_options(&mut state, None, Some(ROUTE)).unwrap();
    state.api_inventory[1].source_route = Some(SECOND_ROUTE.into());
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::Complete;
        item.attempts = 3;
        item.e2e_current = true;
        item.verified_target_fingerprint = Some("old-target".into());
    }
    state.phase = RewritePhase::SliceComplete;
    state.group_id = Some("old-group".into());
    state.e2e_current = true;
    // Model the on-disk shape written before the persistent route catalog existed.
    state.source_route_bindings.clear();
    state
}

fn rerecord(state: &mut RewriteState, reason: RewriteRecordingReason) {
    let root = tempfile::tempdir().unwrap();
    reset_for_fresh_recording(
        root.path(),
        state,
        RewriteRecordingSettings::default(),
        reason,
    )
    .unwrap();
}

#[test]
fn legacy_routes_survive_rerecord_and_restart_without_reusing_verification() {
    for reason in [
        RewriteRecordingReason::UserRequested,
        RewriteRecordingReason::RecorderContractChanged,
    ] {
        let root = tempfile::tempdir().unwrap();
        let store = RewriteStore::new(root.path()).unwrap();
        store.save(&legacy_state()).unwrap();
        let mut state = store.load().unwrap().unwrap();
        rerecord(&mut state, reason);
        assert!(state.api_inventory.is_empty());
        assert!(state.group_id.is_none());
        assert!(!state.e2e_current);
        // Scope changes may reset the inventory again before the recording starts.
        state.recording_apis = vec![API.into()];
        inventory::reset_for_recording(&mut state);
        store.save(&state).unwrap();

        let mut state = store.load().unwrap().unwrap();
        inventory::install(&mut state, vec![API.into(), SECOND_API.into()]).unwrap();
        assert_eq!(state.source_route, ROUTE);
        assert!(!inventory::current_requires_source_route(&state));
        assert_eq!(
            state.api_inventory[1].source_route.as_deref(),
            Some(SECOND_ROUTE)
        );
        for item in &state.api_inventory {
            assert_eq!(item.attempts, 0);
            assert!(!item.e2e_current);
            assert!(item.verified_target_fingerprint.is_none());
        }
        store.save(&state).unwrap();
        assert!(!inventory::current_requires_source_route(
            &store.load().unwrap().unwrap()
        ));
    }
}

#[test]
fn temporarily_unrecorded_api_keeps_its_route_for_a_later_batch() {
    let mut state = legacy_state();
    rerecord(&mut state, RewriteRecordingReason::UserRequested);
    inventory::install(&mut state, vec![SECOND_API.into()]).unwrap();
    assert_eq!(state.source_route, SECOND_ROUTE);
    rerecord(&mut state, RewriteRecordingReason::UserRequested);
    inventory::install(&mut state, vec![API.into()]).unwrap();
    assert_eq!(state.source_route, ROUTE);
    assert!(!inventory::current_requires_source_route(&state));
}

#[test]
fn newly_recorded_patterns_use_the_pattern_without_another_source_confirmation() {
    for new_api in [
        "POST /api/tasks/*",
        "GET /api/tasks/*/details",
        "GET /api/tasks/**",
    ] {
        let mut state = legacy_state();
        rerecord(&mut state, RewriteRecordingReason::UserRequested);
        inventory::install(&mut state, vec![new_api.into()]).unwrap();
        assert!(!inventory::current_requires_source_route(&state));
        assert_eq!(
            state.api_inventory[0].source_route.as_deref(),
            Some(new_api.split_once(' ').unwrap().1)
        );
    }
}

#[test]
fn invalid_legacy_or_cached_routes_are_not_reused() {
    let mut state = legacy_state();
    state.source_route = "/tasks/{id}".into();
    state.api_inventory[0].source_route = Some("/tasks/{id}".into());
    state.api_inventory[1].source_route = Some("/api/users/42".into());
    state
        .source_route_bindings
        .insert(API.into(), "/wrong/{id}".into());
    rerecord(&mut state, RewriteRecordingReason::UserRequested);
    inventory::install(&mut state, vec![API.into(), SECOND_API.into()]).unwrap();
    assert!(!inventory::current_requires_source_route(&state));
    assert_eq!(state.source_route, "/api/tasks/*");
    assert_eq!(
        state.api_inventory[1].source_route.as_deref(),
        Some("/api/users/*")
    );
}

#[test]
fn source_baseline_change_discards_old_bindings_and_accepts_new_confirmation() {
    let mut state = legacy_state();
    rerecord(&mut state, RewriteRecordingReason::UserRequested);
    inventory::install(&mut state, vec![API.into()]).unwrap();
    rerecord(&mut state, RewriteRecordingReason::SourceBaselineChanged);
    assert!(state.source_route_bindings.is_empty());
    inventory::install(&mut state, vec![API.into(), SECOND_API.into()]).unwrap();
    assert!(!inventory::current_requires_source_route(&state));
    assert_eq!(state.source_route, "/api/tasks/*");
    assert_eq!(
        state.api_inventory[1].source_route.as_deref(),
        Some("/api/users/*")
    );
    let updated_route = "/api/tasks/{new_id}";
    bind_options(&mut state, None, Some(updated_route)).unwrap();
    rerecord(&mut state, RewriteRecordingReason::UserRequested);
    inventory::install(&mut state, vec![API.into()]).unwrap();
    assert_eq!(state.source_route, updated_route);
}
