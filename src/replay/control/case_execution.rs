//! Active execution failures exclude merely unused Source inventory.
use super::*;
use serde::Serialize;

const MAX_FAILURES: usize = 8;

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
    let mut failures = Vec::new();
    // The primary request polls this endpoint while replay is still running.
    // Its bounded diagnostic does not need unused inventory or signed witnesses.
    macro_rules! project {
        ($protocol:literal, $($kind:literal => $events:expr),+ $(,)?) => {
            $(append_failures(
                &mut failures,
                $protocol,
                $kind,
                $events.iter().filter(|entry| entry.case_id.as_deref() == Some(case)),
            );)+
        };
    }
    project!("mysql",
        "unmatched_queries" => state.mysql.events.unmatched_queries,
        "unsupported_commands" => state.mysql.events.unsupported_commands,
    );
    project!("http",
        "unmatched_http_requests" => state.http_events.unmatched,
        "unsupported_http_exchanges" => state.http_events.unsupported,
    );
    project!("network", "unrecorded_targets" => state.unrecorded_targets);
    project!("redis",
        "unmatched" => state.redis.events.unmatched,
        "unsupported" => state.redis.events.unsupported,
        "unsafe_events" => state.redis.events.unsafe_events,
    );
    if failures.len() < MAX_FAILURES {
        append_failures(
            &mut failures,
            "redis",
            "unsafe_events",
            state
                .redis
                .derived_unsafe_events()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
    }
    project!("kafka",
        "unmatched" => state.kafka.events.unmatched,
        "unsupported" => state.kafka.events.unsupported,
        "unsafe_events" => state.kafka.events.unsafe_events,
    );
    project!("memcached",
        "unmatched" => state.memcached.events.unmatched,
        "unsupported" => state.memcached.events.unsupported,
        "unsafe_events" => state.memcached.events.unsafe_events,
    );
    project!("motan",
        "unmatched" => state.motan.events.unmatched,
        "unsupported" => state.motan.events.unsupported,
        "unsafe_events" => state.motan.events.unsafe_events,
    );
    serde_json::json!({"ok":true,"case_id":case,"failed":true,"failures":failures,
        "has_response_time_copies":has_response_time_copies})
}

fn append_failures<T: Serialize>(
    failures: &mut Vec<Value>,
    protocol: &str,
    kind: &str,
    entries: impl Iterator<Item = T>,
) {
    for entry in entries.take(MAX_FAILURES - failures.len()) {
        let entry = serde_json::to_value(entry).expect("Replay failure serializes");
        let mut failure = serde_json::json!({"protocol":protocol,"kind":kind});
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
