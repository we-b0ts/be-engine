//! An engine refresh must not preempt the worker dispatched for a real failure.
use super::*;
use crate::worker::model::{
    RewriteWorkerActivity as Activity, RewriteWorkerCoverageState as Coverage,
};

fn dispatched() -> (RewriteState, RewriteWorkScope) {
    let mut state = runtime_state(Some(crate::build_info::ENGINE_FINGERPRINT));
    worker::confirm_current_for_test(&mut state);
    let scope = api_selector::work_scope(&state, &state.api);
    state.attempts[0].engine_fingerprint = Some("engine-revision-v1:older".into());
    (state, scope)
}

#[test]
fn engine_refresh_retains_running_and_queued_dispatch_without_consuming_a_retry() {
    for activity in [Activity::Running, Activity::Queued] {
        for expired in [false, true] {
            let (mut state, scope) = dispatched();
            let observation = state
                .worker_bindings
                .get_mut(&scope.binding_key())
                .unwrap()
                .observation
                .as_mut()
                .unwrap();
            observation.activity = activity;
            if expired {
                observation.observed_at = "2000-01-01T00:00:00Z".into();
            }
            let binding = serde_json::to_value(&state.worker_bindings).unwrap();
            let issue = serde_json::to_value(&state.active_issue).unwrap();
            assert!(eligible(
                &state.active_slice,
                crate::build_info::ENGINE_FINGERPRINT
            ));
            assert!(!pending(&state, &state.active_slice));
            assert!(worker::runtime::scopes(&state).contains(&scope));
            assert_eq!(
                worker::runtime::coverage(&state, &scope),
                if expired {
                    Coverage::StatusRequired
                } else {
                    Coverage::Running
                }
            );
            assert!(!reserve(&mut state, None));
            assert!(state.engine_retry_fingerprints.is_empty());
            assert_eq!(
                serde_json::to_value(&state.worker_bindings).unwrap(),
                binding
            );
            assert_eq!(serde_json::to_value(&state.active_issue).unwrap(), issue);
            assert_eq!(state.attempts.len(), 1);
        }
    }
}

#[test]
fn engine_refresh_does_not_treat_stale_identity_or_idle_work_as_an_active_dispatch() {
    for mode in 0..5 {
        let (mut state, scope) = dispatched();
        let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
        match mode {
            0 => binding.confirmed_dispatch_id = "unconfirmed".into(),
            1 => binding.observation.as_mut().unwrap().dispatch_id = "old-dispatch".into(),
            2 => binding.observation.as_mut().unwrap().recording_run_id = "old-recording".into(),
            3 => binding.observation.as_mut().unwrap().activity = Activity::Idle,
            _ => binding.observation.as_mut().unwrap().activity = Activity::ReworkRequired,
        }
        assert!(pending(&state, &state.active_slice), "mode={mode}");
        assert!(reserve(&mut state, None));
    }
}
