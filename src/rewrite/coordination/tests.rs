use crate::rewrite::{self, model::*, store::RewriteStore, worker};
use worker::tests::{configured_target, implementation_state_with_inventory};

#[test]
fn multiple_methods_share_one_verification_and_revalidation_work_item() {
    let mut state = rewrite::test_state();
    rewrite::inventory::install(&mut state, vec!["GET /api".into(), "PUT /api".into()]).unwrap();
    let action = RewriteAction::Complete {
        summary: "test projection".into(),
        e2e_current: false,
    };
    let projected = super::details(&state, &action, false);
    assert_eq!(projected.ready.get("verify_api"), Some(&1));
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::RevalidationPending;
    }
    state.phase = RewritePhase::SliceComplete;
    let projected = super::details(&state, &action, false);
    assert_eq!(projected.waiting.get("final_revalidation"), Some(&1));
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    assert_eq!(super::details(&state, &action, false).completed, 0);
    state.api_inventory[1].status = RewriteApiStatus::Complete;
    assert_eq!(super::details(&state, &action, false).completed, 1);
}

fn repair_with_workers(revision: String) -> RewriteState {
    let mut state = implementation_state_with_inventory(false);
    for index in 1..=12 {
        let api = format!("GET /worker-{index}");
        let mut item = state.api_inventory[0].clone();
        item.api = api.clone();
        item.status = RewriteApiStatus::ImplementationRequired;
        state.api_inventory.push(item);
        let mut slice = state.active_slice.clone();
        slice.api = api.clone();
        state.parked_slices.insert(api, slice);
    }
    state.phase = RewritePhase::SystemRepairRequired;
    state.route = Some(RewriteRouteRecord {
        kind: "replay_capability_gap".into(),
        evidence_id: "repair-evidence".into(),
        source_ref: "src/replay.rs:1".into(),
        required_change: "support the recorded exchange".into(),
        repair_id: Some("repair-current".into()),
        acceptance_kind: Some(RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged),
        observed_revision: Some(revision),
        legacy_acceptance_command: None,
    });
    state
}

#[test]
fn ready_repair_is_counted_globally_and_selected_before_worker_dispatch() {
    let target = configured_target();
    let state = repair_with_workers("previous-engine".into());
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let context = || rewrite::RewriteContext {
        target_root: target.path().into(),
    };
    let global = rewrite::status_rewrite(context()).unwrap();
    let scoped =
        rewrite::status_rewrite_for_api(context(), Some(&state.api.parse().unwrap())).unwrap();
    let worker =
        rewrite::status_rewrite_for_api(context(), Some(&"GET /worker-1".parse().unwrap()))
            .unwrap();
    let inventory = rewrite::inventory_rewrite(context()).unwrap();
    assert_eq!(global.pending, 13);
    assert_eq!(scoped.pending, global.pending);
    assert_eq!(worker.pending, global.pending);
    assert!(matches!(
        worker.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    assert_eq!(inventory.pending, global.pending);
    assert_eq!(inventory.details.ready["verify_system_repair"], 1);
    assert_eq!(inventory.details.ready["dispatch_worker"], 12);
    let action = serde_json::to_value(&global).unwrap();
    assert_eq!(action["workflow"].as_object().unwrap().len(), 2);
    assert_eq!(action["action"]["kind"], "system_repair_required");
    assert_eq!(
        action["action"]["details"]["work_scope"]["api"],
        crate::rewrite::api_selector::public_api(&state.api)
    );
    assert_eq!(action["action"]["details"]["acceptance_ready"], true);
    assert_eq!(
        action["action"]["commands"]["acceptance"]["argv"][4],
        "verify"
    );
    assert_eq!(
        serde_json::to_value(inventory).unwrap()["workflow"]["phase"],
        "system_repair_required"
    );
    assert_eq!(store.load().unwrap().unwrap().revision, state.revision);
}

#[test]
fn unchanged_repair_waits_without_blocking_other_workers() {
    let target = configured_target();
    let state = repair_with_workers(rewrite::fingerprint::traffic_e2e_revision().unwrap());
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = || rewrite::RewriteContext {
        target_root: target.path().into(),
    };
    let status = rewrite::status_rewrite(context()).unwrap();
    let scoped =
        rewrite::status_rewrite_for_api(context(), Some(&state.api.parse().unwrap())).unwrap();
    let inventory = rewrite::inventory_rewrite(context()).unwrap();
    assert_eq!(status.pending, 12);
    assert_eq!(scoped.pending, 12);
    assert_eq!(inventory.pending, 12);
    assert!(matches!(
        status.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    assert!(matches!(
        scoped.action,
        RewriteAction::SystemRepairRequired {
            acceptance: None,
            ..
        }
    ));
    assert_eq!(inventory.details.waiting["system_repair"], 1);
    assert!(!inventory.details.ready.contains_key("verify_system_repair"));
}

#[test]
fn repair_acceptance_waits_for_resource_while_dispatch_remains_ready() {
    let target = configured_target();
    let state = repair_with_workers("previous-engine".into());
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let _lock = store.lock().unwrap();
    let context = || rewrite::RewriteContext {
        target_root: target.path().into(),
    };
    let status = rewrite::status_rewrite(context()).unwrap();
    let inventory = rewrite::inventory_rewrite(context()).unwrap();
    assert_eq!(status.pending, 12);
    assert_eq!(inventory.pending, status.pending);
    assert_eq!(inventory.details.waiting["system_repair"], 1);
    assert!(matches!(
        status.action,
        RewriteAction::ImplementationRequired { .. }
    ));
}

#[test]
fn initialized_project_without_workflow_starts_from_read_only_status() {
    let target = configured_target();
    let context = || rewrite::RewriteContext {
        target_root: target.path().into(),
    };
    let status = rewrite::status_rewrite(context()).unwrap();
    assert!(!status.initialized);
    assert_eq!(status.pending, 1);
    let RewriteAction::AdvanceRequired { command, .. } = status.action else {
        panic!("start the workflow")
    };
    assert_eq!(command.argv.last().unwrap(), "next");
    assert_eq!(rewrite::inventory_rewrite(context()).unwrap().pending, 1);
    assert!(
        RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .is_none()
    );
}
