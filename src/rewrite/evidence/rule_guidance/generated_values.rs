//! Difference-triggered authoring hints; source proof and plan validation remain mandatory.
use super::*;

fn has_header_difference(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match value {
        Value::Object(fields) => {
            fields
                .get("pointer")
                .and_then(Value::as_str)
                .is_some_and(|pointer| pointer.starts_with("$headers/"))
                || fields
                    .get("header_date_candidates")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty())
                || fields
                    .values()
                    .any(|value| has_header_difference(value, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .any(|value| has_header_difference(value, depth + 1)),
        _ => false,
    }
}

pub(super) fn hints(root: &Path, query: &str, facts: &Value) -> Vec<RewriteRuleHint> {
    let mut hints = Vec::new();
    if query == QUERY_REPRESENTATIVES && has_header_difference(facts, 0) {
        hints.push(RewriteRuleHint {
            capability: "response_header_date".into(), rule: "header-date".into(),
            hint: "A response header difference can contain a current-date filename. Review header_date_candidates, then prove the source date format and timezone. Use rule plan --header-date with the header and optional parameter (filename also checks filename*), apply, and fresh Replay. Each side must use its own request's calendar date; disposition, filename prefix/extension, other parameters, multiplicity and body remain checked. Existing recordings are reusable.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(),"plan".into(),"--help".into()], Vec::new()),
        });
    }
    if query == QUERY_DIRTY_CLUSTERS
        && (facts["dynamic_capture_candidates"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
            || facts["clusters"].as_array().is_some_and(|items| {
                items.iter().any(|cluster| {
                    cluster["protocol"] == "mysql" && cluster["reason"] == "unmatched_target"
                })
            }))
    {
        hints.push(RewriteRuleHint {
            capability: "dynamic_value".into(), rule: "dynamic-value".into(),
            hint: "If a source-generated identity differs in decoded dependency requests, trace its generator and lifetime. Inspect dynamic_capture_candidates for Redis/HTTP witnesses. Use rule plan --dynamic-value with one MySQL SQL value, Redis SET/HSET value, or HTTP JSON pointer capture, exact allowed host/port endpoints, and source evidence. The applied dependency_rules entry uses kind: dynamic_value. Format is optional. Apply and fresh Replay bind one consistent case-local identity across decoded requests without listing each reference. Fixed values, authentication/database, finite consumption and case ownership remain strict; hashes and opaque binary payloads are not inferred.".into(),
            help: super::super::super::action::command(root, vec!["rule".into(),"plan".into(),"--help".into()], Vec::new()),
        });
    }
    hints
}

pub(super) fn planners(
    root: &Path,
    kind: RewriteIssueKind,
    query: &str,
    facts: &Value,
    evidence_id: &str,
) -> Vec<RewriteApplicableRulePlanner> {
    if !matches!(
        kind,
        RewriteIssueKind::Response
            | RewriteIssueKind::Replay
            | RewriteIssueKind::Dependency
            | RewriteIssueKind::Comparison
    ) {
        return Vec::new();
    }
    hints(root, query, facts)
        .into_iter()
        .filter(|hint| hint.capability != "dynamic_value" || kind != RewriteIssueKind::Comparison)
        .map(|hint| RewriteApplicableRulePlanner {
            kind: hint.capability.clone(),
            capability: hint.capability,
            evidence_id: evidence_id.into(),
            command: super::super::super::action::command(
                root,
                vec![
                    "rule".into(),
                    "plan".into(),
                    "--evidence-id".into(),
                    evidence_id.into(),
                    "--help".into(),
                ],
                Vec::new(),
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn header_rules_are_offered_without_body_codecs_and_identity_rules_require_capture_evidence() {
        let root = Path::new("/target");
        let facts = json!({"representative":{"pointer":"$headers/content-disposition"}});
        assert!(
            super::super::rule_hints(root, QUERY_REPRESENTATIVES, &facts)
                .iter()
                .any(|hint| hint.capability == "response_header_date")
        );
        let facts = json!({"clusters":[{"protocol":"mysql","reason":"unmatched_target"}]});
        assert_eq!(hints(root, QUERY_DIRTY_CLUSTERS, &facts).len(), 1);
        assert!(hints(root, QUERY_REPRESENTATIVES, &json!({})).is_empty());
        assert_eq!(
            hints(
                root,
                QUERY_DIRTY_CLUSTERS,
                &json!({"dynamic_capture_candidates":[{"capture":{"protocol":"redis"}}]})
            )
            .len(),
            1
        );
        assert_eq!(
            hints(
                root,
                QUERY_DIRTY_CLUSTERS,
                &json!({"dynamic_capture_candidates":[{"capture":{"protocol":"http"}}]})
            )
            .len(),
            1
        );
        assert!(
            planners(
                root,
                RewriteIssueKind::Comparison,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "evidence"
            )
            .is_empty()
        );
    }
}
