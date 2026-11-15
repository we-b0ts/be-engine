//! Active execution failures exclude merely unused Source inventory.
use super::*;
use traffic_replay::case::append_failure_summaries;

const MAX_FAILURES: usize = 8;

pub(super) fn failed<P: ReplayProtocolSet>(state: &RuntimeState<P>, case: &str) -> bool {
    state.dependency_tails.failure(case).is_some()
        || state.native.case_has_runtime_failure(case)
        || state.unrecorded_case_ids.contains(case)
        || state.protocols.case_has_runtime_failure(case)
}

pub(super) fn status<P: ReplayProtocolSet>(state: &RuntimeState<P>, case: Option<&str>) -> Value {
    let has_response_time_copies = case.is_some_and(|case| {
        state
            .replay_policy
            .as_ref()
            .is_some_and(|policy| policy.contracts().has_time_copies(case))
    });
    if let Some(case) = case
        && let Some(failure) = state.dependency_tails.failure(case)
    {
        return serde_json::json!({"ok":true,"case_id":case,"failed":true,
            "kind":failure["kind"],"failures":[failure],
            "has_response_time_copies":has_response_time_copies});
    }
    let Some(case) = case.filter(|case| state.active_case_id.as_deref() == Some(*case)) else {
        return serde_json::json!({"ok":false,"error":"case_execution_status requires the active Case"});
    };
    if !failed(state, case) {
        return serde_json::json!({"ok":true,"case_id":case,"failed":false,"failures":[],
            "has_response_time_copies":has_response_time_copies});
    }
    let mut failures = state.native.failures_for_case(case, MAX_FAILURES);
    state
        .protocols
        .append_case_failures(case, &mut failures, MAX_FAILURES);
    append_failure_summaries(
        &mut failures,
        MAX_FAILURES,
        "network",
        "unrecorded_targets",
        state
            .unrecorded_targets
            .iter()
            .filter(|entry| entry.case_id.as_deref() == Some(case)),
    );
    serde_json::json!({"ok":true,"case_id":case,"failed":true,"failures":failures,
        "has_response_time_copies":has_response_time_copies})
}
