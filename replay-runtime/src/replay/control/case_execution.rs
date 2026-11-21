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
    let flags = case
        .map(|case| match &state.replay_policy {
            Some(policy) => policy.contracts().case_flags(case),
            None => state.native.contracts.case_flags(case),
        })
        .unwrap_or_default();
    if let Some(case) = case
        && let Some(failure) = state.dependency_tails.failure(case)
    {
        return with_flags(
            serde_json::json!({"ok":true,"case_id":case,"failed":true,
            "kind":failure["kind"],"failures":[failure]}),
            flags,
        );
    }
    let Some(case) = case.filter(|case| state.active_case_id.as_deref() == Some(*case)) else {
        return serde_json::json!({"ok":false,"error":"case_execution_status requires the active Case"});
    };
    if !failed(state, case) {
        return with_flags(
            serde_json::json!({"ok":true,"case_id":case,"failed":false,"failures":[]}),
            flags,
        );
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
    with_flags(
        serde_json::json!({"ok":true,"case_id":case,"failed":true,"failures":failures}),
        flags,
    )
}

fn with_flags(mut status: Value, flags: BTreeMap<String, Value>) -> Value {
    let object = status.as_object_mut().expect("case status is an object");
    for (name, value) in flags {
        object.entry(name).or_insert(value);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_flags_preserve_framework_execution_facts() {
        let status = with_flags(
            serde_json::json!({"ok":true,"failed":true}),
            BTreeMap::from([
                ("failed".into(), Value::Bool(false)),
                ("extension_ready".into(), Value::Bool(true)),
            ]),
        );
        assert_eq!(status["failed"], true);
        assert_eq!(status["extension_ready"], true);
    }
}
