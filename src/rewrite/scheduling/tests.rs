use super::*;
use crate::rewrite::{self, model::*, store::RewriteStore, worker};
use worker::tests::{configured_target, implementation_state_with_inventory};

fn with_revalidation(count: usize) -> RewriteState {
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    for index in 0..count {
        let mut item = state.api_inventory[0].clone();
        item.api = format!("GET /revalidate-{index}");
        item.source_route = Some(format!("/revalidate-{index}"));
        item.status = RewriteApiStatus::RevalidationPending;
        state.api_inventory.push(item);
    }
    state
}

fn mark_repair(state: &mut RewriteState) {
    state.phase = RewritePhase::SystemRepairRequired;
    state.route = Some(RewriteRouteRecord {
        kind: "replay_capability_gap".into(),
        evidence_id: "repair-evidence".into(),
        source_ref: "src/replay.rs:1".into(),
        required_change: "support the recorded exchange".into(),
        repair_id: Some(format!("repair-{}", state.api)),
        acceptance_kind: Some(RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged),
        observed_revision: Some(rewrite::fingerprint::traffic_e2e_revision().unwrap()),
        legacy_acceptance_command: None,
    });
}

fn status(root: &Path) -> RewriteStatusReport {
    rewrite::status_rewrite(rewrite::RewriteContext {
        target_root: root.into(),
    })
    .unwrap()
}

fn assert_advance(action: &RewriteAction, api: &str) {
    let RewriteAction::AdvanceRequired { command, .. } = action else {
        panic!("expected advance to {api}, got {action:?}")
    };
    assert_eq!(command.argv.last().unwrap(), api);
}

#[test]
fn screenshot_running_worker_and_thirty_stale_apis_selects_one_without_mutation() {
    let target = configured_target();
    let state = with_revalidation(30);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let report = status(target.path());
    assert_eq!(report.pending, 1);
    assert_advance(&report.action, "GET /revalidate-0");
    let inventory = rewrite::inventory_rewrite(rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(inventory.pending, report.pending);
    assert_eq!(inventory.details.ready["revalidate_api"], 1);
    assert_eq!(inventory.details.waiting["final_revalidation"], 29);
    assert_eq!(inventory.details.waiting["worker_handoff"], 1);
    let scoped = rewrite::status_rewrite_for_api(
        rewrite::RewriteContext {
            target_root: target.path().into(),
        },
        Some(&"GET /revalidate-0".parse().unwrap()),
    )
    .unwrap();
    assert_advance(&scoped.action, "GET /revalidate-0");
    assert_eq!(
        before,
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap()
    );
}

#[test]
fn busy_verification_returns_one_executable_wait_and_preserves_worker_identity() {
    let target = configured_target();
    let state = with_revalidation(30);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let _lock = store.lock().unwrap();
    let report = status(target.path());
    assert_eq!(report.pending, 1);
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["action"]["kind"], "wait_required");
    assert_eq!(value["action"]["commands"]["wait"]["argv"][3], "wait");
    assert!(value["action"]["commands"].get("status").is_none());
    assert_eq!(store.load().unwrap().unwrap().worker_bindings.len(), 1);
}

#[test]
fn parked_system_repair_survives_revalidation_and_becomes_resumable_after_revision_change() {
    let target = configured_target();
    let mut state = with_revalidation(2);
    mark_repair(&mut state);
    let original_api = state.api.clone();
    let original_slice = serde_json::to_value(&state.active_slice).unwrap();
    let repair_id = state.route.as_ref().unwrap().repair_id.clone().unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    assert_advance(&status(target.path()).action, "GET /revalidate-0");
    inventory::activate_requested(&mut state, Some(&"GET /revalidate-0".parse().unwrap())).unwrap();
    assert_eq!(
        state.api_inventory[0].status,
        RewriteApiStatus::SystemRepairRequired
    );
    assert_eq!(
        original_slice,
        serde_json::to_value(&state.parked_slices[&original_api]).unwrap()
    );
    assert_eq!(
        inventory::api_for_repair(&state, &repair_id).as_deref(),
        Some(original_api.as_str())
    );
    // A passing revalidation advances only once to the next stale API.
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.target_fingerprint =
        Some(rewrite::fingerprint::repository_fingerprint(target.path()).unwrap());
    assert!(inventory::complete_current_and_advance(&mut state).unwrap());
    assert_eq!(state.api, "GET /revalidate-1");
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.target_fingerprint =
        Some(rewrite::fingerprint::repository_fingerprint(target.path()).unwrap());
    assert!(!inventory::complete_current_and_advance(&mut state).unwrap());
    store.save(&state).unwrap();
    let blocked = status(target.path());
    assert_eq!(blocked.pending, 0);
    assert!(!blocked.terminal_allowed);
    assert!(
        matches!(blocked.action, RewriteAction::Blocked { ref system_repair_apis, .. } if system_repair_apis == std::slice::from_ref(&original_api))
    );
    assert_eq!(status(target.path()).pending, 0);
    // The stop is projected, not persisted as a terminal workflow phase.
    state
        .parked_slices
        .get_mut(&original_api)
        .unwrap()
        .route
        .as_mut()
        .unwrap()
        .observed_revision = Some("older-engine".into());
    store.save(&state).unwrap();
    let resumed = status(target.path());
    assert_eq!(resumed.pending, 1);
    assert!(matches!(
        resumed.action,
        RewriteAction::SystemRepairRequired {
            acceptance: Some(_),
            ..
        }
    ));
    rewrite::verify_rewrite_repair(
        rewrite::RewriteContext {
            target_root: target.path().into(),
        },
        &repair_id,
    )
    .unwrap();
    let accepted = store.load().unwrap().unwrap();
    assert_eq!(accepted.api, original_api);
    assert!(accepted.system_repair_accepted);
    assert_eq!(accepted.api_inventory[1].status, RewriteApiStatus::Complete);
}

#[tokio::test]
async fn integrated_handoff_can_advance_while_another_api_waits_for_system_repair() {
    let target = configured_target();
    let mut state = with_revalidation(1);
    let worker_api = state.api.clone();
    worker::integrate_current_for_test(&mut state);
    inventory::activate_requested(&mut state, Some(&"GET /revalidate-0".parse().unwrap())).unwrap();
    state.active_issue = state.parked_slices[&worker_api].active_issue.clone();
    mark_repair(&mut state);
    let repair_slice = serde_json::to_value(&state.active_slice).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    assert!(matches!(
        status(target.path()).action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    let result = rewrite::next_rewrite(rewrite::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        process_output: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        result.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.api, "GET /revalidate-0");
    assert_eq!(
        repair_slice,
        serde_json::to_value(&state.active_slice).unwrap()
    );
}

#[test]
fn new_implementation_issue_preempts_revalidation_then_releases_it_after_dispatch() {
    let target = configured_target();
    let mut state = with_revalidation(2);
    state.worker_bindings.clear();
    let first = action::for_state(target.path(), &state);
    assert!(matches!(
        first.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    worker::confirm_current_for_test(&mut state);
    assert_advance(
        &action::for_state(target.path(), &state).action,
        "GET /revalidate-0",
    );
}

#[test]
fn all_repair_items_stop_but_a_running_worker_still_requires_wait() {
    let target = configured_target();
    let mut state = with_revalidation(0);
    let waiting = action::for_state(target.path(), &state);
    assert_eq!(waiting.pending, 1);
    assert!(matches!(waiting.action, RewriteAction::WaitRequired { .. }));
    mark_repair(&mut state);
    let blocked = action::for_state(target.path(), &state);
    assert_eq!(blocked.pending, 0);
    assert!(matches!(blocked.action, RewriteAction::Blocked { .. }));
    let view = inventory::view(&state);
    assert_eq!(view.system_repair_required, 1);
    assert_eq!(view.active, 0);
    assert_eq!(view.total, view.system_repair_required + view.completed);
    assert_eq!(
        inventory::details(&state).items[0].status,
        RewriteApiStatus::SystemRepairRequired
    );
}

#[tokio::test]
async fn wait_returns_runtime_reconciliation_without_fabricating_activity() {
    let target = configured_target();
    let state = with_revalidation(0);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    let started = std::time::Instant::now();
    let result = rewrite::wait_rewrite(rewrite::RewriteWaitOptions {
        target_root: target.path().into(),
        seconds: 1,
    })
    .await
    .unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert_eq!(result.pending, 1);
    assert!(matches!(
        result.action,
        RewriteAction::WorkerEventsRequired { .. }
    ));
    assert_eq!(
        before,
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap()
    );
}

#[tokio::test]
async fn wait_returns_immediately_for_blocked_stop() {
    let target = configured_target();
    let mut state = with_revalidation(0);
    mark_repair(&mut state);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rewrite::wait_rewrite(rewrite::RewriteWaitOptions {
            target_root: target.path().into(),
            seconds: 30,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.pending, 0);
    assert!(!result.terminal_allowed);
    assert!(matches!(result.action, RewriteAction::Blocked { .. }));
}

#[tokio::test]
async fn wait_wakes_for_reported_worker_interruption_before_its_deadline() {
    let target = configured_target();
    let state = with_revalidation(0);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let scope = rewrite::RewriteWorkScope::Api {
        api: state.api.clone(),
    };
    let wait = rewrite::wait_rewrite(rewrite::RewriteWaitOptions {
        target_root: target.path().into(),
        seconds: 30,
    });
    let report = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        worker::runtime::report(worker::runtime::RewriteWorkerReportOptions {
            review_report: None,
            target_root: target.path().into(),
            dispatch_id: worker::dispatch_view(&state, scope.clone(), None).dispatch_id,
            agent_handle: format!("test-subagent-handle:{}", scope.binding_key()),
            activity: worker::model::RewriteWorkerActivity::Idle,
            handoff_id: None,
        })
        .unwrap();
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(wait, report)
    })
    .await
    .unwrap();
    assert!(matches!(
        result.unwrap().action,
        RewriteAction::WorkerEventsRequired { .. }
    ));
    assert!(matches!(
        status(target.path()).action,
        RewriteAction::ImplementationRequired { .. }
    ));
}

#[test]
fn recording_and_comparison_gates_cannot_be_parked_for_idle_revalidation() {
    let target = configured_target();
    for phase in [
        RewritePhase::RecordingRequired,
        RewritePhase::ComparisonRecordingRequired,
    ] {
        let mut state = with_revalidation(1);
        state.phase = phase;
        state.comparison_run_id = Some("comparison-test".into());
        state.recording_require_comparison = true;
        assert!(idle_action(target.path(), &state).is_none());
        assert!(
            inventory::activate_requested(&mut state, Some(&"GET /revalidate-0".parse().unwrap()))
                .is_err()
        );
    }
}

#[test]
fn blocked_stop_preserves_dependent_outputs_and_does_not_hide_output_workers() {
    use rewrite::process_output_model::{RewriteProcessOutputProgress, RewriteProcessOutputStatus};
    let target = configured_target();
    let mut state = with_revalidation(0);
    mark_repair(&mut state);
    state
        .process_outputs
        .inventory
        .push(RewriteProcessOutputProgress {
            id: "profile".into(),
            status: RewriteProcessOutputStatus::RevalidationPending,
            attempts: 1,
            verified_target_fingerprint: None,
            issue: None,
        });
    let blocked = action::for_state(target.path(), &state);
    assert!(
        matches!(blocked.action, RewriteAction::Blocked { ref dependent_process_outputs, .. } if dependent_process_outputs == &["profile"])
    );
    state.process_outputs.inventory[0].status = RewriteProcessOutputStatus::ImplementationRequired;
    state.process_outputs.inventory[0].issue = state.active_issue.clone();
    let dispatch = action::for_state(target.path(), &state);
    assert!(dispatch.pending > 0);
    assert!(matches!(
        dispatch.action,
        RewriteAction::ImplementationRequired { .. }
    ));
}

#[test]
fn completed_evidence_is_revalidated_again_only_after_target_changes() {
    let target = configured_target();
    let mut state = with_revalidation(1);
    mark_repair(&mut state);
    inventory::activate_requested(&mut state, Some(&"GET /revalidate-0".parse().unwrap())).unwrap();
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.target_fingerprint = Some("target-v1".into());
    assert!(!inventory::complete_current_and_advance(&mut state).unwrap());
    assert!(!inventory::defer_completed_for_target_change(&mut state, "target-v1").unwrap());
    assert!(matches!(
        action::for_state(target.path(), &state).action,
        RewriteAction::Blocked { .. }
    ));
    assert!(inventory::defer_completed_for_target_change(&mut state, "target-v2").unwrap());
    assert_eq!(state.phase, RewritePhase::ApiPending);
    assert_advance(
        &action::for_state(target.path(), &state).action,
        "GET /revalidate-0",
    );
}
