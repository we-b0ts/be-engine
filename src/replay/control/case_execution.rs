//! Active execution failures exclude merely unused Source inventory.
use super::*;

pub(super) fn failed(state: &ReplayState, case: &str) -> bool {
    state.dependency_tails.failure(case).is_some()
        || state.unrecorded_case_ids.contains(case)
        || state.mysql.events.dirty_case_ids.contains(case)
        || state.redis.case_has_runtime_failure(case)
        || state.http_events.case_has_runtime_failure(case)
        || state.kafka.case_has_runtime_failure(case)
        || state.memcached.case_has_runtime_failure(case)
        || state.motan.case_has_runtime_failure(case)
}

pub(super) fn status(state: &ReplayState, case: Option<&str>) -> Value {
    let has_response_time_copies = case.is_some_and(|case| {
        state
            .replay_policy
            .as_ref()
            .is_some_and(|policy| policy.request_contracts.has_time_copies(case))
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
    let report = serde_json::to_value(state.snapshot_report()).expect("Replay report serializes");
    let mut failures = Vec::new();
    for (protocol, parent, fields) in [
        (
            "mysql",
            &report,
            &["unmatched_queries", "unsupported_commands"][..],
        ),
        (
            "http",
            &report,
            &["unmatched_http_requests", "unsupported_http_exchanges"][..],
        ),
        ("network", &report, &["unrecorded_targets"][..]),
        (
            "redis",
            &report["redis"],
            &["unmatched", "unsupported", "unsafe_events"][..],
        ),
        (
            "kafka",
            &report["kafka"],
            &["unmatched", "unsupported", "unsafe_events"][..],
        ),
        (
            "memcached",
            &report["memcached"],
            &["unmatched", "unsupported", "unsafe_events"][..],
        ),
        (
            "motan",
            &report["motan"],
            &["unmatched", "unsupported", "unsafe_events"][..],
        ),
    ] {
        for field in fields {
            for entry in parent[*field]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|entry| entry["case_id"] == case)
            {
                if failures.len() == 8 {
                    break;
                }
                let mut failure = serde_json::json!({"protocol":protocol,"kind":field});
                for key in [
                    "command",
                    "method",
                    "reason",
                    "target_event_index",
                    "diagnostic",
                ] {
                    if let Some(value) = entry.get(key) {
                        failure[key] = value.clone();
                    }
                }
                failures.push(failure);
            }
        }
    }
    serde_json::json!({"ok":true,"case_id":case,"failed":true,"failures":failures,
        "has_response_time_copies":has_response_time_copies})
}
