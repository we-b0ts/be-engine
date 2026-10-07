use super::*;
use crate::rewrite::{RewritePhase, inventory, test_support::test_state, worker};

#[test]
fn route_selector_preserves_method_contracts_and_exact_path_boundaries() {
    let mut state = test_state();
    state.route_worker_scopes = true;
    inventory::install(
        &mut state,
        vec![
            "DELETE /api/subscriptions/*".into(),
            "PUT /api/subscriptions/*".into(),
            "POST /api/subscriptions/*/trigger".into(),
        ],
    )
    .unwrap();
    let selector = "/api/subscriptions/*".parse().unwrap();
    assert_eq!(members(&state, &selector).len(), 2);
    assert_eq!(
        members(&state, &"PUT /api/subscriptions/*".parse().unwrap()),
        vec!["PUT /api/subscriptions/*"]
    );
    assert!(
        "GET|PUT /api/subscriptions/*"
            .parse::<RewriteApiSelector>()
            .is_err()
    );
    assert!(
        "/api/subscriptions/* "
            .parse::<RewriteApiSelector>()
            .is_err()
    );
    assert_eq!(
        work_scope(&state, &state.api).binding_key(),
        "/api/subscriptions/*"
    );
}

#[test]
fn new_route_worker_reserves_all_methods_and_exposes_one_task() {
    let mut state = worker::tests::implementation_state_with_inventory(false);
    state.route_worker_scopes = true;
    inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = worker::tests::implementation_state_with_inventory(false)
        .active_issue
        .clone();
    let mut sibling = state.active_slice.clone();
    sibling.api = "PUT /api".into();
    sibling.active_issue.as_mut().unwrap().id = "issue-put".into();
    state.parked_slices.insert(sibling.api.clone(), sibling);
    let scopes = worker::runtime::scopes(&state);
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].binding_key(), "/api");
    worker::confirm_current_for_test(&mut state);
    assert!(worker::ensure_api_confirmed(&state, "PUT /api", "test").is_ok());
    let dispatch = worker::dispatch_view(&state, scopes[0].clone(), None).dispatch_id;
    let selected = inventory::scoped(&state, Some(&"PUT /api".parse().unwrap())).unwrap();
    assert_eq!(
        dispatch,
        worker::dispatch_view(&selected, scopes[0].clone(), None).dispatch_id
    );
}

#[test]
fn legacy_snapshot_upgrade_keeps_existing_worker_identity_and_method_progress() {
    let target = worker::tests::configured_target();
    let mut state = worker::tests::implementation_state_with_inventory(true);
    worker::confirm_current_for_test(&mut state);
    let scope = work_scope(&state, &state.api);
    let before = worker::dispatch_view(&state, scope.clone(), None);
    let store = super::RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let path = crate::internal_runtime::root(target.path()).join("rewrite/state.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    document
        .as_object_mut()
        .unwrap()
        .remove("route_worker_scopes");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let restored = store.load().unwrap().unwrap();
    assert!(restored.route_worker_scopes);
    let after = worker::dispatch_view(&restored, scope, None);
    assert_eq!(before.binding_id, after.binding_id);
    assert_eq!(before.dispatch_id, after.dispatch_id);
    assert_eq!(after.work_scope.binding_key(), "GET /api");
    assert_eq!(work_scope(&restored, "POST /other").binding_key(), "/other");
    assert_eq!(restored.api_inventory.len(), 2);
}
