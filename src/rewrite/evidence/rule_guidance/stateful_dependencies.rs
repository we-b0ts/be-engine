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
                    "redis_finite_process_get",
                    "redis_read_commutation",
                    "redis_read_observation",
                    "redis_read_back",
                    "redis_state_observations",
                    "redis_activity_refresh",
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
        }
    }
    if query == QUERY_UNIFIED_RULE_CANDIDATES {
        for entry in facts["source_entry"]["locations"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let binding = &entry["location"];
            if !matches!(
                binding["surface"].as_str(),
                Some("dependency.request" | "dependency.response")
            ) {
                continue;
            }
            if let Some("redis") = binding["match"]["resource"]["protocol"].as_str() {
                match binding["match"]["operation"].as_str() {
                    Some("APPEND") => {
                        capabilities.insert("redis_append_stream");
                    }
                    Some("GET") => {
                        capabilities.extend([
                            "redis_finite_process_get",
                            "redis_read_commutation",
                            "redis_read_observation",
                            "redis_read_back",
                            "redis_state_observations",
                            "redis_activity_refresh",
                        ]);
                    }
                    Some("LRANGE") => {
                        capabilities.insert("redis_read_back");
                    }
                    Some("EXPIRE") => {
                        capabilities.insert("redis_expiry_refresh");
                    }
                    _ => {}
                }
            }
        }
    }
    capabilities
        .into_iter()
        .map(|capability| RewriteRuleHint {
            capability: capability.into(),
            rule: capability.into(),
            hint: format!(
                "This is a supported capability to investigate from bounded operation facts, not proof that a rule applies or that the engine has a gap. {} Use fresh Source file:line proof and a self-contained traffic-policy/v2 rule; rule plan --file <rule.yaml> --evidence <evidence-id> validates complete Source coverage. Inspect the immutable plan, apply, and run fresh genuine Replay with unchanged recordings. Counts, equal responses and missing candidates grant no permission.",
                instruction(capability)
            ),
            help: help(root),
        })
        .collect()
}

fn instruction(capability: &str) -> &'static str {
    match capability {
        "redis_activity_refresh" => {
            "Declare redis.keys.<bounded-pattern>.activity_refresh: {fields: [/last_activity_at]} only for Source-proven metadata heartbeat refreshes; timestamp formats remain in json.fields. Prove the complete isolated SET/GET/DEL lifetime, byte-exact current-value Source reads, stable unselected object fields and one unchanged positive EX TTL. Target GET returns its current matched SET value, and each refresh SET requires an actual delivered GET and changes only declared current timestamps. Creation/deletion, stream bytes and content/list reads stay finite. No absent-key polling, arbitrary writes, APPEND permission or skipped reads is granted. See docs/redis-activity-refresh.md."
        }
        "redis_finite_process_get" => {
            "For independently proven process work, declare process_dependencies.tasks.<actual-task>.requests with redis operation: GET, bounded ports and exact keys, omitting initial_load_timeout_ms. Every original response stays single-use, changing values stay distinct, and exhaustion fails. A task name is a grouping label, not captured issuer provenance: prove every selected Source occurrence independently of request paths, including sibling APIs using the same key. Existing snapshot seeds/hits cannot supply finite evidence. This classification grants no default response, wildcard, stateful-session relaxation or reuse; adding a positive initial_load_timeout_ms instead retains initialization snapshot acquisition and its fresh-recording obligation. See docs/process-owned-redis.md."
        }
        "redis_append_stream" => {
            "Declare redis.keys.<bounded-pattern>.append_stream: true for Source-proven ordered APPEND buffering. Prove complete writers, initial length, causal order and read/reset fences. Resource/database selectors are not authored; preparation and runtime partition actual endpoint, database and authentication identities. Every byte remains exact; other calls and finite TTL counts need their own proof. redis_append_stream_mismatch and redis_append_stream_boundary_mismatch identify a rejected byte prefix or early fence: inspect the cursor and required offset. See docs/redis-append-stream.md."
        }
        "redis_read_commutation" => {
            "Declare redis.keys.<bounded-pattern>.read_commutation: true for finite nil GETs commuting with unrelated commands. Prove complete nil reads, only no-op DEL cleanup, independent Source scheduling and no shared, mutated or stateful ownership. Every recorded read remains required and extra reads fail. GET presence or lane_blocked alone does not prove nil values or independence. Actual resource/database/authentication partitions remain strict. See docs/redis-read-commutation.md."
        }
        "redis_read_observation" => {
            "Declare redis.keys.<bounded-pattern>.read_observation: true only for Source-proven absent-state polling between owned single-key DEL/UNLINK boundaries. Prove the independent poll loop, complete nil responses, closing deletion and absence of writers, expiry observers, foreign ownership or transactions. Repeats/coalescing require a delivered initial deletion and a Source witness in the current epoch; historical reads stay finite and the closing deletion ends permission. Both mutations remain required. This does not authorize non-nil or always-false cancellation handling. See docs/redis-absent-read-observations.md."
        }
        "redis_expiry_refresh" => {
            "Declare redis.keys.<bounded-pattern>.expiry_refresh: true for count-equivalent EXPIRE calls inside one proven key lifetime. Prove successful ordinary Case creation, one exact positive TTL, no expiry observers or external ownership, and complete causal Source traces shorter than the TTL. One delivered refresh must cover each observed lifetime; creation/deletion and ordinary writes remain finite. EXPIRE presence alone does not prove these prerequisites. See docs/redis-state-observations.md."
        }
        "redis_read_back" => {
            "Global JSON and scalar identity formats already reuse established same-Case Target values and anchor unknown inputs. For Source-proven variable GET observations of the latest raw SET identity, declare kind: identity, formats and read_back: true on the same redis.keys pattern. Prove complete same-key SET/DEL lifetimes and a positive write-to-read witness; historical reads before an owned write remain finite. Actual endpoint/database/authentication and causality remain checked. Additional list or compound native write/read relationships retain their typed contracts and finite counts. See docs/redis-read-back.md."
        }
        "redis_state_observations" => {
            "redis.keys.<bounded-pattern>.read_back: true enables Source-proven current-identity GET state observations with the key scalar identity format. Supply independent Source proof on the proposed key declaration, not an authored state_epochs or binding graph. A positive write-to-read witness and complete causal SET/DEL history are required. Historical reads before the first owned SET stay finite; no future, deleted, other-resource or other-user identity can be borrowed. Investigate redis_state_observation_mismatch at its reported state mutation. See docs/redis-state-observations.md."
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
