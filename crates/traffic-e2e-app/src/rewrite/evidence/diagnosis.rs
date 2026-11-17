//! Bounded implementer guidance from retained issues and actual execution facts.
//! This projection performs no discovery, ownership proof or rule authorization.
use super::*;

const GROUP_LIMIT: usize = 6;

pub(super) fn overview(
    state: &RewriteState,
    issue: &RewriteIssue,
    facts: &Value,
    queries: &[RewriteEvidenceCommand],
) -> Value {
    let failures = facts["execution_failures"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let unconsumed = execution::has_unconsumed_dependencies(failures);
    let rejected = execution::has_rejected_dependencies(failures);
    let interrupted = facts["primary_failure"]["kind"] == "replay_interrupted";
    let focus = if interrupted || issue.kind == RewriteIssueKind::TargetRuntime {
        "target_runtime"
    } else if issue.kind == RewriteIssueKind::TargetQuality {
        "target_quality"
    } else if rejected && unconsumed {
        "dependency_execution"
    } else if rejected {
        "dependency_request"
    } else if unconsumed {
        "unconsumed_dependencies"
    } else {
        match issue.kind {
            RewriteIssueKind::Dependency => "dependency_inventory",
            RewriteIssueKind::Replay => "replay_execution",
            _ => "response",
        }
    };
    let query = |kind| {
        let id = query_id(state, issue, kind);
        queries
            .iter()
            .find(|query| query.query_id == id)
            .map(|query| query.query_id.as_str())
    };
    let mut next_queries = Vec::new();
    let mut next = |kind, reason: &str| {
        if let Some(id) = query(kind) {
            next_queries.push(json!({"query_id":id,"reason":reason}));
        }
    };
    match focus {
        "target_runtime" | "replay_execution" => next(
            QUERY_TARGET_RUNTIME_DIAGNOSTICS,
            "Inspect the actual runtime or Replay interruption before interpreting downstream differences.",
        ),
        "dependency_request"
        | "dependency_execution"
        | "unconsumed_dependencies"
        | "dependency_inventory" => {
            next(
                QUERY_DIRTY_CLUSTERS,
                "Locate the rejected request or required unconsumed Source call and inspect its exact native constraints.",
            );
        }
        "response" => next(
            QUERY_CASE_RESPONSE_DIFFERENCES,
            "Read expected/actual values with explicit presence in this Case; trace the differing output to Source and Target construction.",
        ),
        _ => {}
    }
    if facts["execution_failures_summary"]["omitted"]
        .as_u64()
        .is_some_and(|n| n > 0)
    {
        next(
            execution::KIND,
            "Read omitted Cases before making an API-wide conclusion; each Case retains its own cause.",
        );
    }
    let mut strategies = Vec::new();
    if focus == "target_quality" {
        strategies.push(
            json!({"kind":"target_repair","strategy":"repair_delivery_findings",
            "condition":"Address context.delivery.required_repairs in the assigned worktree."}),
        );
    } else if focus == "target_runtime" || focus == "replay_execution" {
        strategies.push(json!({"kind":"investigation","strategy":"runtime_diagnosis",
            "query_id":query(QUERY_TARGET_RUNTIME_DIAGNOSTICS),
            "condition":"Use observed startup, transport and lifecycle failures to distinguish Target environment from an engine defect."}));
    } else {
        strategies.push(json!({"kind":"target_repair","strategy":"source_compatible_behavior",
            "condition":if unconsumed {"Trace the required Source calls and asynchronous continuation; implement the missing or misordered Target work."}
                else {"Trace the exact mismatch to Source and Target construction, client arguments and configuration; repair proven behavior differences."},
            "proof_required":"Source and Target code for this Case and native operation; issue hypotheses alone are not a root cause."}));
        let lane_blocked = failures
            .iter()
            .flat_map(|case| case["failures"].as_array().into_iter().flatten())
            .any(|failure| failure["diagnostic"]["kind"] == "lane_blocked");
        if lane_blocked {
            strategies.push(json!({"kind":"investigation","strategy":"native_request_order",
                "query_id":query(QUERY_DIRTY_CLUSTERS),
                "condition":"A recorded predecessor blocks a later Target request. Inspect diagnostic.blocked_by and candidate in the same Case and lane.",
                "proof_required":"Prove the corresponding Source call, ordering and finite consumption before choosing a code repair or a supported native contract. A value format alone cannot waive a missing predecessor."}));
        }
        let response_value_difference = issue.kind == RewriteIssueKind::Response
            && !unconsumed
            && issue.representative.as_ref().is_some_and(|difference| {
                difference.pointer != "$status"
                    && difference.difference_kind != ResponseDifferenceKind::ResponseUnavailable
            });
        if rejected || response_value_difference {
            strategies.push(json!({"kind":"policy_candidate","strategy":"source_proven_value_contract",
                "status":"requires_difference_and_source_proof",
                "query_id":query(QUERY_UNIFIED_RULE_CANDIDATES),
                "condition":"Only when exact differences and Source construction prove generated time/identity, a supported encoding, or non-contractual collection order.",
                "proof_required":"Prove each format, clock or identity relationship from Source. Use the detail evidence ID for coordinator plan/apply and fresh Replay; missing calls, statuses, events and native order remain required."}));
        }
        if issue.kind == RewriteIssueKind::Dependency && !rejected && !unconsumed {
            strategies.push(json!({"kind":"policy_candidate","strategy":"source_dependency_ownership",
                "status":"requires_occurrence_and_source_proof",
                "query_id":query(QUERY_API_INFORMATION),
                "condition":"Only for unused Source occurrences that independent Source analysis proves belong to another API or an actual process task.",
                "proof_required":"Exact physical occurrence identities and independent task/API ownership. Classification does not match a rejected Target request or create consumption."}));
        }
    }
    json!({"focus":focus,"method_api":state.api,"attempt":issue.attempt,
        "mismatches":mismatch_groups(failures),
        "response_difference":issue.representative.as_ref().map(|difference| json!({
            "case_id":difference.case_id,"pointer":difference.pointer,
            "observation_pointer":"/facts/issue/representative"})),
        "execution_coverage":facts["execution_failures_summary"],
        "next_queries":next_queries,"strategies":strategies,
        "strategy_boundary":"Candidates guide investigation; applicability is unproven until Source proof and the returned detail query validate it."})
}

fn mismatch_groups(failures: &[Value]) -> Value {
    let mut groups = BTreeMap::<(String, String, String, String, String), Value>::new();
    for (case_index, case) in failures.iter().enumerate() {
        for (index, failure) in case["failures"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let text = |name| failure[name].as_str().unwrap_or("unavailable").to_string();
            let key = (
                text("protocol"),
                text("command"),
                text("kind"),
                text("reason"),
                failure["diagnostic"]["kind"]
                    .as_str()
                    .unwrap_or("unavailable")
                    .to_string(),
            );
            let group = groups.entry(key).or_insert_with(|| json!({
                "protocol":failure["protocol"],"command":failure["command"],
                "kind":failure["kind"],"reason":failure["reason"],"occurrences_in_overview":0,
                "native_constraint":failure["diagnostic"]["kind"],
                "representative":{"case_id":case["case_id"],"target_event_index":failure["target_event_index"],
                    "evidence_pointer":format!("/facts/execution_failures/{case_index}/failures/{index}")}}));
            group["occurrences_in_overview"] =
                (group["occurrences_in_overview"].as_u64().unwrap_or(0) + 1).into();
        }
    }
    json!({"coverage":"overview execution failures only; not whole API totals",
        "total_groups_in_overview":groups.len(),"omitted_groups":groups.len().saturating_sub(GROUP_LIMIT),
        "groups":groups.into_values().take(GROUP_LIMIT).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests;
