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
            target_root: target.path().into(),
            dispatch_id: dispatch.dispatch_id.clone(),
            agent_handle: format!("actual-runtime-worker-{remaining}"),
            agent_name: None,
        })
        .unwrap();
        assert_eq!(response.pending, remaining);
        let response = runtime::report(runtime::RewriteWorkerReportOptions {
            target_root: target.path().into(),
            dispatch_id: dispatch.dispatch_id,
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
    let RewriteAction::AdvanceRequired { command, .. } = status.action else {
        panic!("replay the accepted repair")
    };
    assert_eq!(command.argv.last().unwrap(), "GET /api-01");
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
        api: "GET /api-01".into(),
    };
    let mut parked = runtime::scoped(&state, &scope).unwrap();
    worker::integrate_current_for_test(&mut parked);
    state.worker_bindings = parked.worker_bindings;
    store.save(&state).unwrap();
    let envelope = rewrite::next_rewrite(RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        process_output: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert_eq!(envelope.pending, 1);
    let RewriteAction::TargetQualityRequired { command, .. } = envelope.action else {
        panic!("integrated API must pass quality gates first")
    };
    assert_eq!(command.argv.last().unwrap(), "GET /api-01");
    let latest = store.load().unwrap().unwrap();
    assert_eq!(latest.api, "GET /api-01");
    assert_eq!(
        latest.parked_slices["GET /api"].phase,
        RewritePhase::ImplementationRequired
    );
    assert_eq!(
        runtime::coverage(
            &latest,
            &rewrite::RewriteWorkScope::Api {
                api: "GET /api".into()
            }
        ),
        Coverage::Running
    );
}
