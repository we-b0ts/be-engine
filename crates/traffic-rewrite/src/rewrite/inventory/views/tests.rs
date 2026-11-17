use super::*;
use crate::rewrite::{inventory, test_support::test_state};

#[test]
fn current_index_addresses_route_items_and_method_evidence_remains_explicit() {
    let mut state = test_state();
    inventory::install(
        &mut state,
        vec![
            "GET /orders/*".into(),
            "POST /other".into(),
            "PUT /orders/*".into(),
            "MOTAN /orders/*".into(),
        ],
    )
    .unwrap();
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    let mut state = inventory::scoped(&state, Some(&"PUT /orders/*".parse().unwrap())).unwrap();
    state.api_inventory[2].status = RewriteApiStatus::Active;
    state.source_route = "/orders/{order_id}".into();
    state.e2e_current = true;
    let before = serde_json::to_value(&state).unwrap();
    let report = details(&state);
    assert_eq!(report.summary.total, 3);
    assert_eq!(report.summary.current_api.as_deref(), Some("/orders/*"));
    assert_eq!(report.summary.current_index, Some(0));
    assert_eq!(report.summary.active, 1);
    assert_eq!(report.summary.pending, 2);
    assert_eq!(report.items[0].api, "/orders/*");
    assert_eq!(report.items[0].methods.len(), 2);
    assert_eq!(report.items[0].methods[0].api, "GET /orders/*");
    assert_eq!(
        report.items[0].methods[0].status,
        RewriteApiStatus::Complete
    );
    assert_eq!(report.items[0].methods[1].api, "PUT /orders/*");
    assert!(report.items[0].methods[1].e2e_current);
    assert_eq!(
        report.items[0].methods[1].source_route.as_deref(),
        Some("/orders/{order_id}")
    );
    assert_eq!(report.items[1].api, "/other");
    assert_eq!(report.items[2].api, "MOTAN /orders/*");
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    let value = serde_json::to_value(&report).unwrap();
    assert!(value.get("current_route").is_none());
    assert_eq!(value["total"], value["items"].as_array().unwrap().len());
}

#[test]
fn a_passing_method_cannot_complete_an_unverified_or_failing_sibling() {
    let mut state = test_state();
    inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    assert_eq!(view(&state).completed, 0);
    assert_eq!(view(&state).pending, 1);
    state.api_inventory[1].status = RewriteApiStatus::ImplementationRequired;
    assert_eq!(view(&state).completed, 0);
    assert_eq!(view(&state).implementation_required, 1);
    state.api_inventory[1].status = RewriteApiStatus::Complete;
    assert_eq!(view(&state).completed, 1);
    assert_eq!(details(&state).items[0].status, RewriteApiStatus::Complete);
}

#[test]
fn excluded_methods_do_not_block_completion_or_count_as_skipped_routes() {
    let mut state = test_state();
    inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    state.api_inventory[1].status = RewriteApiStatus::Skipped;
    assert_eq!(view(&state).active, 1);
    assert_eq!(view(&state).skipped, 0);
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    assert_eq!(view(&state).completed, 1);
    assert_eq!(view(&state).skipped, 0);
    state.api_inventory[0].status = RewriteApiStatus::Skipped;
    state.current_api_index = None;
    let summary = view(&state);
    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.completed, 0);
    let value = serde_json::to_value(&summary).unwrap();
    assert!(value.get("current_index").is_none());
    assert!(value.get("current_api").is_none());
}

#[test]
fn route_counts_form_one_partition_and_prioritize_unresolved_blockers() {
    let mut state = test_state();
    inventory::install(
        &mut state,
        vec![
            "GET /blocked".into(),
            "PUT /blocked".into(),
            "GET /refresh".into(),
            "GET /implementation".into(),
            "GET /active".into(),
            "GET /revalidate".into(),
            "GET /pending".into(),
            "GET /complete".into(),
            "GET /skip".into(),
        ],
    )
    .unwrap();
    for (item, status) in state.api_inventory.iter_mut().zip([
        RewriteApiStatus::Active,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::AwaitingRecordingRefresh,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::Active,
        RewriteApiStatus::RevalidationPending,
        RewriteApiStatus::Pending,
        RewriteApiStatus::Complete,
        RewriteApiStatus::Skipped,
    ]) {
        item.status = status;
    }
    state.phase = RewritePhase::SystemRepairRequired;
    let summary = view(&state);
    assert_eq!(summary.total, 8);
    assert_eq!(summary.system_repair_required, 1);
    assert_eq!(summary.implementation_required, 1);
    assert_eq!(summary.active, 1);
    assert_eq!(summary.awaiting_recording_refresh, 1);
    assert_eq!(summary.revalidation_pending, 1);
    assert_eq!(summary.pending, 1);
    assert_eq!(summary.completed, 1);
    assert_eq!(summary.skipped, 1);
    state.phase = RewritePhase::ApiPending;
    assert_eq!(view(&state).implementation_required, 2);
    assert_eq!(view(&state).system_repair_required, 0);
    assert_eq!(view(&state).active, 1);
}

#[test]
fn route_display_and_worker_scope_share_one_identity_without_changing_method_progress() {
    let mut state = test_state();
    inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    let report = details(&state);
    assert_eq!(report.summary.total, 1);
    assert_eq!(report.summary.current_api.as_deref(), Some("/api"));
    assert_eq!(state.api, "GET /api");
    assert_eq!(state.api_inventory.len(), 2);
    assert_eq!(
        crate::rewrite::api_selector::work_scope(&state, &state.api).binding_key(),
        "/api"
    );
}
