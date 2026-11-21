use super::*;
use crate::{api_selector::RewriteApiSelector, workflow_test_support::test_state};

#[test]
fn route_inventory_keeps_skipped_methods_separate() {
    let mut state = test_state();
    inventory::install(
        &mut state,
        vec![
            "GET /api".into(),
            "PUT /api".into(),
            "POST /api/other".into(),
        ],
    )
    .unwrap();
    state.api_inventory[1].status = RewriteApiStatus::Skipped;
    let selector = RewriteApiSelector::Route("/api".into());
    assert_eq!(
        api_selector::members(&state, &selector),
        vec!["GET /api", "PUT /api"]
    );
    assert_eq!(
        api_selector::select(&state, &selector).unwrap().to_string(),
        "GET /api"
    );
    assert_eq!(state.api_inventory[1].status, RewriteApiStatus::Skipped);
}

fn result(api: &str, passed: bool) -> crate::E2eApiRunResult {
    serde_json::from_value(serde_json::json!({
        "run_key": "20260802000000", "api": api, "attempt": 1,
        "status": if passed { "successful" } else { "failed" }, "passed": passed,
        "gates": { "responses": if passed { "passed" } else { "nonpassing" },
            "replay": "complete", "dependencies": "clean" },
        "diagnosis": { "counts": { "selected": 1, "executed": 1,
            "response_passed": u32::from(passed), "response_nonpassing": u32::from(!passed), "response_incomplete": 0 },
            "response_differences": { "total_differences": 0, "indexed_differences": 0, "omitted_differences": 0,
                "failure_clusters": [], "omitted_failure_clusters": 0 }, "representative": null },
        "progress": ".traffic-e2e/progress.yaml"
    })).unwrap()
}

#[test]
fn route_transition_preserves_passed_and_skipped_methods_and_one_worker_scope() {
    let target = crate::worker::tests::configured_target();
    let mut state = test_state();
    inventory::install(
        &mut state,
        vec!["GET /api".into(), "PUT /api".into(), "PATCH /api".into()],
    )
    .unwrap();
    state.api_inventory[2].status = RewriteApiStatus::Skipped;
    apply_results(
        target.path(),
        &mut state,
        &[result("GET /api", true), result("PUT /api", false)],
        None,
    )
    .unwrap();
    assert_eq!(state.api, "PUT /api");
    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Complete);
    assert_eq!(state.api_inventory[2].status, RewriteApiStatus::Skipped);
    assert!(state.parked_slices["GET /api"].e2e_current);
    let scopes = crate::worker::runtime::scopes(&state);
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].binding_key(), "/api");
}

#[test]
fn route_completion_requires_every_method_and_preserves_method_history() {
    let target = crate::worker::tests::configured_target();
    let mut state = test_state();
    inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    apply_results(
        target.path(),
        &mut state,
        &[result("GET /api", true), result("PUT /api", true)],
        None,
    )
    .unwrap();
    assert_eq!(state.phase, RewritePhase::SliceComplete);
    assert_eq!(state.current_api_index, None);
    assert!(
        state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Complete && item.attempts == 1)
    );
    assert!(crate::worker::runtime::scopes(&state).is_empty());
}

#[test]
fn route_acceptance_never_replays_a_completed_or_deferred_sibling() {
    let mut state = test_state();
    inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    state.api_inventory[1].status = RewriteApiStatus::Complete;
    assert_eq!(replayable_methods(&state), vec!["GET /api"]);
    state.api_inventory[1].status = RewriteApiStatus::RevalidationPending;
    assert_eq!(replayable_methods(&state), vec!["GET /api"]);
    // Both methods join a new round only after implementation acceptance drains.
    state.api_inventory[0].status = RewriteApiStatus::RevalidationPending;
    state.phase = RewritePhase::SliceComplete;
    state.current_api_index = None;
    inventory::activate_requested(&mut state, Some(&"GET /api".parse().unwrap())).unwrap();
    assert_eq!(replayable_methods(&state), vec!["GET /api", "PUT /api"]);
    inventory::revalidation_round::finish(&mut state, "GET /api");
    state.api_inventory[0].status = RewriteApiStatus::ImplementationRequired;
    let selector = RewriteApiSelector::Route("/api".into());
    assert_eq!(
        api_selector::select(&state, &selector).unwrap().to_string(),
        "PUT /api"
    );
    assert_eq!(replayable_methods(&state), vec!["PUT /api"]);
}

#[test]
fn failed_route_batch_keeps_the_remaining_round_ahead_of_its_worker() {
    let target = crate::worker::tests::configured_target();
    let mut state = test_state();
    inventory::install(
        &mut state,
        vec!["GET /api".into(), "PUT /api".into(), "GET /other".into()],
    )
    .unwrap();
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::RevalidationPending;
    }
    state.phase = RewritePhase::SliceComplete;
    state.current_api_index = None;
    inventory::activate_requested(&mut state, Some(&"GET /api".parse().unwrap())).unwrap();
    apply_results(
        target.path(),
        &mut state,
        &[result("GET /api", false), result("PUT /api", false)],
        None,
    )
    .unwrap();
    assert_eq!(state.api, "GET /other");
    assert_eq!(state.phase, RewritePhase::ApiPending);
    assert_eq!(
        inventory::revalidation_round::next(&state),
        Some("GET /other")
    );
    assert_eq!(
        state.parked_slices["GET /api"].phase,
        RewritePhase::ImplementationRequired
    );
    assert_eq!(
        state.parked_slices["PUT /api"].phase,
        RewritePhase::ImplementationRequired
    );
}
