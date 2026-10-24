//! A physical-field inventory is useful before a mechanical strategy draft exists.
use super::*;

fn has_source_bindings(query: &str, facts: &Value) -> bool {
    query == QUERY_UNIFIED_RULE_CANDIDATES
        && facts["source_entry"]["bindings"]
            .as_array()
            .is_some_and(|bindings| !bindings.is_empty())
}

pub(super) fn hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    if !has_source_bindings(query, facts) {
        return Vec::new();
    }
    vec![RewriteRuleHint {
        capability: "resource_field_contract".into(),
        rule: "resource-fields".into(),
        hint: "Inspect source_entry.bindings even when candidates is empty. First inventory the physical locations and Source semantics: MySQL database/table/column plus decoded pointer, Redis key/container/hash-field plus pointer, and response API/body or SSE event/pointer. Reuse existing declarations and codecs. Declare time format/relation, duration unit/branch, unordered consumer semantics or a generated identity's eligibility and format once at its owning field. Storage contracts have no API, SQL template or argument ordinal. For an identity, request every eligible location in one proposal and assign one case-local binding domain; runtime preserves the Source equality partition, including distinct IDs, across MySQL, Redis and response. Reads deliver an established Target ID; an unknown delivered ID anchors itself. A generator location is useful Source evidence, not a mandatory first capture rule. Mixed fixed/external IDs need proven eligibility guards; a whole-column declaration is unsafe when that distinction cannot be expressed, so retain its narrow native owner. Keep null/empty/sentinel values exact unless explicitly guarded. Native rules add only extra clock sharing, derivation, signatures, state transitions or finite behavior, using field_ref where supported. Plan the complete inventory together, inspect Source coverage and retained Target failures, then apply and finish genuine Replay. Discovery is bounded and never grants permission. See docs/resource-field-contracts.md.".into(),
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
    ) || !has_source_bindings(query, facts)
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
    fn physical_bindings_offer_planning_without_a_mechanical_draft() {
        let root = Path::new("/target");
        let facts = serde_json::json!({"candidates":[],"source_entry":{"bindings":[{
            "binding":{"surface":"dependency.request","match":{"resource":{"protocol":"mysql"}}},
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
                &serde_json::json!({"candidates":[],"source_entry":{"bindings":[]}})
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
