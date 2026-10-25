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
        hint: "Inspect source_entry.locations and trace Source construction, even when no draft exists. Root json.fields supports time, identity, unordered collections, JWT/URL and string templates. Explicit carrier bindings cover encrypted content, DOCX, HTTP paths and learned-response addresses when Source proves them; consult docs/content-policy-layout.md for syntax. Submit only the needed additions with Source proof and the current evidence ID. Equal/null observations grant no permission. Review complete plan coverage and residual differences, then complete genuine Replay.".into(),
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
