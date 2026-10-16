use super::*;
use crate::rewrite::model::RewritePhase;
use crate::rewrite::{self, RewriteContext, RewriteNextOptions, store::RewriteStore, worker};
use worker::tests::{configured_target, implementation_state_with_inventory};

fn many_issues(count: usize) -> RewriteState {
    let mut state = implementation_state_with_inventory(false);
    for index in 1..count {
        let api = format!("GET /api-{index:02}");
        let mut item = state.api_inventory[0].clone();
        item.api = api.clone();
        item.status = rewrite::model::RewriteApiStatus::ImplementationRequired;
        state.api_inventory.push(item);
        let mut slice = state.active_slice.clone();
        slice.api = api.clone();
        state.parked_slices.insert(api, slice);
    }
    state
}

fn ready_handoff_with_pending_api() -> RewriteState {
    let mut state = implementation_state_with_inventory(true);
    worker::confirm_current_for_test(&mut state);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    let observation = state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    observation.activity = worker::model::RewriteWorkerActivity::HandoffReady;
    observation.handoff_id = Some("ready-handoff".into());
    state
}

#[test]
fn first_pass_api_verification_preempts_ready_handoff_integration() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&ready_handoff_with_pending_api()).unwrap();

    let status = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    let RewriteAction::AdvanceRequired { command, api, .. } = status.action else {
        panic!("unattempted API should be verified before integrating a ready handoff")
    };
    assert_eq!(api.as_deref(), Some("/other"));
    assert_eq!(command.argv.last().unwrap(), "next");

    let inventory = rewrite::inventory_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(inventory.pending, 1);
    assert_eq!(inventory.details.ready["verify_api"], 1);
    assert_eq!(inventory.details.waiting["integration_resource"], 1);
    assert!(!inventory.details.ready.contains_key("integrate_handoff"));
}

#[test]
fn ready_handoff_integration_resumes_after_first_pass_discovery() {
    let target = configured_target();
    let mut state = ready_handoff_with_pending_api();
    state.api_inventory.truncate(1);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();

    let status = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(
        matches!(status.action, RewriteAction::IntegrationRequired { .. }),
        "ready handoff should resume after first-pass discovery: {:?}",
        status.action
    );
    let action = serde_json::to_value(&status.action).unwrap();
    assert_eq!(
        action["commands"]["export_batch"]["argv"],
        serde_json::json!([
            "backend-rewrite",
            "--target-root",
            target.path(),
            "review",
            "batch",
            "--api",
            "/api"
        ])
    );
    assert_eq!(
        action["commands"]["export_batch"]["required_env_names"],
        serde_json::json!(["BACKEND_REWRITE_REVIEW_WORKTREE"])
    );
}

#[test]
fn worker_dispatch_still_preempts_first_pass_verification() {
    let target = configured_target();
    let mut state = ready_handoff_with_pending_api();
    let api = "GET /needs-worker";
    let mut item = state.api_inventory[0].clone();
    item.api = api.into();
    item.source_route = Some("/needs-worker".into());
    item.status = rewrite::model::RewriteApiStatus::ImplementationRequired;
    item.attempts = 1;
    state.api_inventory.push(item);
    let mut slice = state.active_slice.clone();
    slice.api = api.into();
    state.parked_slices.insert(api.into(), slice);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();

    let status = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    let RewriteAction::ImplementationRequired { worker, .. } = status.action else {
        panic!("worker dispatch must remain ahead of first-pass verification")
    };
    assert_eq!(worker.work_scope.label(), "API /needs-worker");
}

#[test]
fn all_implementation_items_dispatch_even_with_zero_unverified_and_more_than_32_workers() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = many_issues(40);
    store.save(&state).unwrap();
    // A long verification transaction must not serialize worker dispatch.
    let transition = store.lock().unwrap();
    for remaining in (1..=40).rev() {
        let context = || RewriteContext {
            target_root: target.path().into(),
        };
        let status = rewrite::status_rewrite(context()).unwrap();
        let inventory = rewrite::inventory_rewrite(context()).unwrap();
        assert_eq!(status.api_inventory.as_ref().unwrap().pending, 0);
        assert_eq!(status.pending, remaining);
        assert_eq!(inventory.pending, remaining);
        assert_eq!(inventory.details.ready.values().sum::<usize>(), remaining);
        let RewriteAction::ImplementationRequired {
            worker: dispatch, ..
        } = status.action
        else {
            panic!("every unresolved item must be dispatched")
        };
        let response = worker::confirm(worker::RewriteWorkerConfirmOptions {
            worktree: Some(target.path().to_path_buf()),
            target_root: target.path().into(),
            work_scope: dispatch.work_scope.clone(),
            agent_handle: format!("actual-runtime-worker-{remaining}"),
            agent_name: None,
        })
        .unwrap();
        assert_eq!(response.pending, remaining);
        let response = runtime::report(runtime::RewriteWorkerReportOptions {
            review_report: None,
            target_root: target.path().into(),
            agent_handle: format!("actual-runtime-worker-{remaining}"),
            activity: worker::model::RewriteWorkerActivity::Queued,
            handoff_id: None,
        })
        .unwrap();
        assert_eq!(response.pending, (remaining - 1).max(1));
    }
    // An old verification snapshot cannot overwrite any of the 40 confirmations.
    store.save(&state).unwrap();
    drop(transition);
    let status = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(status.pending, 1);
    assert!(!status.terminal_allowed);
    assert!(matches!(status.action, RewriteAction::WaitRequired { .. }));
    assert_eq!(store.load().unwrap().unwrap().worker_bindings.len(), 40);
}

#[test]
fn accepted_parked_repair_is_scheduled_without_a_new_worker_handoff() {
    let target = configured_target();
    let mut state = many_issues(2);
    worker::confirm_current_for_test(&mut state);
    state
        .parked_slices
        .get_mut("GET /api-01")
        .unwrap()
        .system_repair_accepted = true;
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let status = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(status.pending, 1);
    let RewriteAction::AdvanceRequired { command, api, .. } = status.action else {
        panic!("replay the accepted repair")
    };
    assert_eq!(api.as_deref(), Some("/api-01"));
    assert_eq!(command.argv.last().unwrap(), "next");
    let scoped = rewrite::status_rewrite_for_api(
        RewriteContext {
            target_root: target.path().into(),
        },
        Some(&"GET /api-01".parse().unwrap()),
    )
    .unwrap();
    assert_eq!(scoped.pending, 1);
    assert!(!matches!(
        scoped.action,
        RewriteAction::ImplementationRequired { .. } | RewriteAction::WorkerStatusRequired { .. }
    ));
}

#[tokio::test]
async fn unscoped_next_selects_only_the_parked_integrated_api_and_preserves_quality_gates() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = many_issues(2);
    worker::confirm_current_for_test(&mut state);
    let scope = rewrite::RewriteWorkScope::Api {
        api: "/api-01".into(),
    };
    let mut parked = runtime::scoped(&state, &scope).unwrap();
    worker::integrate_current_for_test(&mut parked);
    state.worker_bindings = parked.worker_bindings;
    store.save(&state).unwrap();
    let envelope = rewrite::next_rewrite(RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert_eq!(envelope.pending, 1);
    let RewriteAction::SourceReviewRequired { check, accept, .. } = envelope.action else {
        panic!("integrated API requires a delivery quality receipt")
    };
    assert!(check.argv.contains(&"--integration".to_string()));
    assert!(accept.argv.contains(&"accept".to_string()));
    let latest = store.load().unwrap().unwrap();
    assert_eq!(latest.api, "GET /api");
    assert_eq!(latest.phase, RewritePhase::ImplementationRequired);
    assert_eq!(
        runtime::coverage(
            &latest,
            &rewrite::RewriteWorkScope::Api { api: "/api".into() }
        ),
        Coverage::Running
    );
}
