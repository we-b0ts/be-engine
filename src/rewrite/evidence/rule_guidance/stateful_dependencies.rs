//! Bounded operation facts reveal supported mechanisms, never stateful permission.
use super::*;

fn signatures(cluster: &Value) -> impl Iterator<Item = &Value> {
    let difference = &cluster["representative"]["difference"];
    ["expected", "actual"].into_iter().filter_map(move |side| {
        let observation = &difference[side];
        (observation["presence"] == "present").then_some(&observation["signature"])
    })
}

fn operation(cluster: &Value, expected: &str) -> bool {
    let matches = |value: &str| value.eq_ignore_ascii_case(expected);
    cluster["operations"]
        .as_object()
        .into_iter()
        .flatten()
        .any(|(name, count)| count.as_u64().is_some_and(|n| n > 0) && matches(name))
        || signatures(cluster).any(|signature| {
            signature["command"].as_str().is_some_and(matches)
                || (signature["diagnostic"]["kind"] == "lane_blocked"
                    && ["candidate", "blocked_by"].into_iter().any(|side| {
                        signature["diagnostic"][side]["command"]
                            .as_str()
                            .is_some_and(matches)
                    }))
        })
}

fn diagnostic(cluster: &Value, expected: &str) -> bool {
    signatures(cluster).any(|signature| signature["diagnostic"]["kind"] == expected)
}

fn mysql_select(cluster: &Value) -> bool {
    operation(cluster, "SELECT")
        || (operation(cluster, "COM_QUERY") || operation(cluster, "COM_STMT_EXECUTE"))
            && signatures(cluster).any(|signature| {
                [
                    &signature["sql"],
                    &signature["sql_summary"],
                    &signature["sql_summary"]["preview"],
                ]
                .into_iter()
                .any(|value| value.as_str().is_some_and(select_sql))
            })
}

fn select_sql(sql: &str) -> bool {
    sql.split_whitespace()
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("SELECT"))
}

pub(super) fn hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    if !matches!(query, QUERY_DIRTY_CLUSTERS | QUERY_UNIFIED_RULE_CANDIDATES) {
        return Vec::new();
    }
    let mut capabilities = std::collections::BTreeSet::new();
    for cluster in facts["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|_| query == QUERY_DIRTY_CLUSTERS)
    {
        if cluster["protocol"] == "redis" {
            if operation(cluster, "APPEND")
                || diagnostic(cluster, "redis_append_stream_mismatch")
                || diagnostic(cluster, "redis_append_stream_boundary_mismatch")
            {
                capabilities.insert("redis_append_stream");
            }
            if operation(cluster, "GET") {
                capabilities.extend([
                    "redis_read_commutation",
                    "redis_read_back",
                    "redis_state_observations",
                ]);
            }
            if operation(cluster, "LRANGE") {
                capabilities.insert("redis_read_back");
            }
            if operation(cluster, "EXPIRE") {
                capabilities.insert("redis_expiry_refresh");
            }
            if diagnostic(cluster, "redis_state_observation_mismatch") {
                capabilities.insert("redis_state_observations");
            }
        } else if cluster["protocol"] == "mysql" && mysql_select(cluster) {
            capabilities.insert("mysql_read_back");
        }
    }
    if query == QUERY_UNIFIED_RULE_CANDIDATES {
        for entry in facts["source_entry"]["bindings"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let binding = &entry["binding"];
            if !matches!(
                binding["surface"].as_str(),
                Some("dependency.request" | "dependency.response")
            ) {
                continue;
            }
            match binding["match"]["resource"]["protocol"].as_str() {
                Some("redis") => match binding["match"]["operation"].as_str() {
                    Some("APPEND") => {
                        capabilities.insert("redis_append_stream");
                    }
                    Some("GET") => {
                        capabilities.extend([
                            "redis_read_commutation",
                            "redis_read_back",
                            "redis_state_observations",
                        ]);
                    }
                    Some("LRANGE") => {
                        capabilities.insert("redis_read_back");
                    }
                    Some("EXPIRE") => {
                        capabilities.insert("redis_expiry_refresh");
                    }
                    _ => {}
                },
                Some("mysql")
                    if binding["surface"] == "dependency.response"
                        && (binding["slot"]["sql_column"].as_str().is_some()
                            || entry["source_response_kind"] == "resultset"
                            || binding["match"]["sql"].as_str().is_some_and(select_sql)) =>
                {
                    capabilities.insert("mysql_read_back");
                }
                _ => {}
            }
        }
    }
    capabilities
        .into_iter()
        .map(|capability| RewriteRuleHint {
            capability: capability.into(),
            rule: capability.into(),
            hint: format!(
                "This is a supported capability to investigate from bounded operation facts, not proof that a rule applies or that the engine has a gap. {} Use fresh Source file:line proof and a self-contained traffic-policy/v1 rule; rule plan --file <rule.yaml> --evidence <evidence-id> validates complete Source coverage. Inspect the immutable plan, apply, and run fresh genuine Replay with unchanged recordings. Counts, equal responses and missing candidates grant no permission.",
                instruction(capability)
            ),
            help: help(root),
        })
        .collect()
}

fn instruction(capability: &str) -> &'static str {
    match capability {
        "redis_append_stream" => {
            "redis_append_stream supports different nonempty APPEND chunk boundaries for one Source-proven ordered byte stream. Scope API, exact Redis endpoint/database/authenticated user, operation APPEND and bounded key family; prove complete writers, initial length, causal order and read/reset fences. Every byte remains exact; other calls and finite TTL counts need their own proof. An existing redis_append_stream_mismatch or redis_append_stream_boundary_mismatch reports a rejected byte prefix or early fence, not missing evidence: inspect the cursor and required offset before changing Target behavior or policy. See docs/redis-append-stream.md."
        }
        "redis_read_commutation" => {
            "redis_read_commutation supports finite nil GETs commuting with unrelated commands. Scope API, exact Redis endpoint/database/authenticated user, operation GET and bounded key; prove complete nil reads, only no-op DEL cleanup, independent Source scheduling and no shared, mutated or stateful ownership. Every recorded read remains required and extra reads fail. GET presence or lane_blocked alone does not prove nil values or independence. See docs/redis-read-commutation.md."
        }
        "redis_expiry_refresh" => {
            "redis_expiry_refresh supports count-equivalent EXPIRE calls inside one proven key lifetime. Scope API, exact Redis endpoint/database/authenticated user, operation EXPIRE and bounded key; prove successful ordinary Case creation, one exact positive TTL, no expiry observers or external ownership, and complete causal Source traces shorter than the TTL. One delivered refresh must cover each observed lifetime; creation/deletion and ordinary writes remain finite. EXPIRE presence alone does not prove these prerequisites. See docs/redis-state-observations.md."
        }
        "redis_read_back" => {
            "An existing identity or redis_sequence write rule can declare effect.read_back for SET argument 1 to GET, RPUSH argument 1 or LSET argument 2 to LRANGE. Trace a preceding successful Target-matched write and the same-key Source read, with exact Case ownership and endpoint/database/user and declared owned JSON fields or raw value. Update the existing write rule with its ID, scope, capture, contracts and prior proofs preserved; give each new declaration its own capture-to-read proof. This changes selected delivered values and retains ordinary ordering and finite counts. See docs/redis-read-back.md."
        }
        "redis_state_observations" => {
            "For Source-proven variable GET counts, an existing raw SET identity read_back can explicitly declare state_epochs with separate Source proof. Scope the same Case ownership and endpoint/database/user and bounded key; prove absence initially and exact current SET/DEL state, causal clocks, no implicit expiry or other writers, and a positive write-to-read witness in the selected inventory. Append a declaration or add state_epochs proof to the otherwise unchanged declaration, preserving existing write scope, contracts and proofs. Each Source-observed state still needs a delivered observation; no future or deleted identity can be borrowed. A typed redis_state_observation_mismatch must be investigated at its reported state mutation rather than treated as missing evidence. See docs/redis-state-observations.md."
        }
        "mysql_read_back" => {
            "An existing identity rule can append effect.mysql_read_back for a Source-persisted identity read from selected MySQL JSON fields. Preserve its ID, capture, scope, references and prior declarations/proofs; the exact read resource must already be an authorized reference. Declare Case ownership, endpoint/database/user, complete SELECT with bounded physical tables, result column and JSON pointers; embedded copies require explicit templates. Prove each leaf's immutable Source capture completed before the Source read; runtime also requires its committed same-Case Target binding. Historical unbound IDs and unselected fields remain unchanged; derived delivery is not independent Target evidence, and SELECTs remain finite. See docs/mysql-identity-read-back.md."
        }
        _ => unreachable!("only bounded supported capabilities are selected"),
    }
}

pub(super) fn planners(
    root: &Path,
    issue: RewriteIssueKind,
    query: &str,
    facts: &Value,
    evidence: &str,
) -> Vec<RewriteApplicableRulePlanner> {
    if !matches!(
        issue,
        RewriteIssueKind::Response | RewriteIssueKind::Dependency | RewriteIssueKind::Replay
    ) {
        return Vec::new();
    }
    hints(root, query, facts)
        .into_iter()
        .map(|hint| RewriteApplicableRulePlanner {
            kind: "dependency_rule".into(),
            capability: hint.capability,
            evidence_id: evidence.into(),
            command: plan_command(root, evidence),
        })
        .collect()
}

#[cfg(test)]
mod tests;
