//! A physical-field inventory is useful before a mechanical strategy draft exists.
use super::*;

fn has_source_locations(query: &str, facts: &Value) -> bool {
    query == QUERY_UNIFIED_RULE_CANDIDATES
        && facts["source_entry"]["locations"]
            .as_array()
            .is_some_and(|bindings| !bindings.is_empty())
}

pub(super) fn hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    if !has_source_locations(query, facts) {
        return Vec::new();
    }
    vec![RewriteRuleHint {
        capability: "resource_field_contract".into(),
        rule: "resource-fields".into(),
        hint: "Inspect source_entry.locations even when candidates is empty, then reuse or extend the global json.fields map. Declare time or identity formats and unordered semantics once per logical pointer, independent of APIs, SSE events, MySQL columns and Redis keys. JSON payloads are recognized automatically. HTTP headers use root http.headers, shared across APIs and endpoints, with case-insensitive names and strict presence/count/order. Enable mysql for native DATE/DATETIME/TIMESTAMP metadata; declare other scalar formats with mysql.tables.<name>.pattern and fields using the same kind/formats syntax. Scalar Redis values use redis.keys patterns and optional redis.database; structured JSON still uses the global JSON map. Source-equal complete typed IDs must be Target-equal; different Source IDs cannot collapse. The engine maintains these relationships internally across supported carriers. Read delivery reuses established Target IDs and anchors unknown inputs. Null/empty/sentinel values and immutable inputs retain their exact behavior. Native effects describe additional clock sharing, derivation, signatures, state transitions or finite behavior. Review complete Source coverage and independent Target evidence, apply, then finish genuine Replay. Discovery is bounded and never grants permission. See docs/resource-field-contracts.md.".into(),
        help: help(root),
    }]
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
    ) || !has_source_locations(query, facts)
    {
        return Vec::new();
    }
    vec![RewriteApplicableRulePlanner {
        kind: "resource_fields".into(),
        capability: "resource_field_contract".into(),
        evidence_id: evidence.into(),
        command: plan_command(root, evidence),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_locations_offer_planning_without_a_mechanical_draft() {
        let root = Path::new("/target");
        let facts = serde_json::json!({"candidates":[],"source_entry":{"locations":[{
            "location":{"surface":"dependency.request","match":{"resource":{"protocol":"mysql"}}},
            "physical_fields":{"fields":[{"table":"tasks","column":"payload"}]}
        }]}});
        assert_eq!(
            super::super::rule_hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &facts).len(),
            1
        );
        for issue in [
            RewriteIssueKind::Response,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Replay,
        ] {
            let planners = super::super::applicable_rule_planners(
                root,
                issue,
                QUERY_UNIFIED_RULE_CANDIDATES,
                &facts,
                "current",
            );
            assert_eq!(planners.len(), 1);
            assert_eq!(planners[0].evidence_id, "current");
            assert!(planners[0].command.argv.contains(&"--file".into()));
            assert!(planners[0].command.argv.contains(&"current".into()));
        }
        assert!(
            planners(
                root,
                RewriteIssueKind::TargetQuality,
                QUERY_UNIFIED_RULE_CANDIDATES,
                &facts,
                "current"
            )
            .is_empty()
        );
        assert!(hints(root, QUERY_DIRTY_CLUSTERS, &facts).is_empty());
        assert!(
            hints(
                root,
                QUERY_UNIFIED_RULE_CANDIDATES,
                &serde_json::json!({"candidates":[],"source_entry":{"locations":[]}})
            )
            .is_empty()
        );
        let mut stale = facts;
        stale["policy_freshness"] = serde_json::json!({"requires_fresh_replay":true});
        assert!(
            super::super::applicable_rule_planners(
                root,
                RewriteIssueKind::Response,
                QUERY_UNIFIED_RULE_CANDIDATES,
                &stale,
                "stale"
            )
            .is_empty()
        );
        let stale_hints = super::super::rule_hints(root, QUERY_UNIFIED_RULE_CANDIDATES, &stale);
        assert_eq!(stale_hints.len(), 1);
        assert_eq!(stale_hints[0].capability, "fresh_replay");
    }
}
