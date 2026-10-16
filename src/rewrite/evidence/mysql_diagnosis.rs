//! Investigation guidance for unconsumed MySQL calls, never an ownership rule.
use serde_json::{Value, json};

fn unused_clusters(facts: &Value) -> impl Iterator<Item = &Value> {
    facts["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|cluster| cluster["protocol"] == "mysql" && cluster["reason"] == "unused_recorded")
}

pub(super) fn attach(facts: &mut Value) {
    let cluster_ids: Vec<_> = unused_clusters(facts)
        .filter_map(|cluster| cluster["cluster_id"].as_str().map(str::to_owned))
        .collect();
    if unused_clusters(facts).next().is_none() {
        return;
    }
    facts["mysql_unused_diagnosis"] = json!({
        "cluster_ids": cluster_ids,
        "observation": "recorded_calls_not_consumed",
        "ownership": "unresolved",
        "source_checks": [
            "Trace the complete request lifecycle, including authentication dependencies and helpers. For ORM reads, inspect commit/rollback, session expiration, explicit refresh, lazy loading and subsequent attribute access; a primary-key read can be an implicit refresh even without an explicit get() call.",
            "Compare the representative SQL, bound values, connection_id, query_sequence and captured server_status_before/server_status_after in dependency details. Status bit 0x0001 is IN_TRANS; absent status is unknown. Physical connections and query sequences locate recorded calls, not source callers or process ownership.",
            "Column aliases and LIMIT shape do not identify an ORM call site. Supported direct-column alias/projection differences already match; check predicates, values, ordering, pagination and finite call consumption before alleging a matching gap."
        ],
        "rule_discovery": {
            "rule_hints": "Capability discovery only; source ownership and rule prerequisites still require proof.",
            "applicable_rule_planners": "Planning entry points, not proof of source ownership or permission to omit calls. Empty candidates or planners do not establish an engine capability gap.",
            "mysql_time": "A time-value rule validates selected generated time slots; it cannot consume an omitted call.",
            "mysql_api_triggered": "Requires a source-proven detached API task and a captured origin identity; it cannot exempt request-owned ORM refreshes."
        },
        "required_behavior": "Business SELECTs remain required, including repeated reads returning equal rows. Optional session cleanup and passing HTTP responses do not make a business read optional. Repair target behavior when source proof establishes the missing request-owned call; otherwise retain unresolved evidence."
    });
}

pub(super) fn limitations(facts: &Value) -> Vec<String> {
    if unused_clusters(facts).next().is_none() {
        return Vec::new();
    }
    vec![
        "unused_recorded means a recorded MySQL call was not consumed; it does not by itself prove an SQL matching defect, optional read or engine capability gap".into(),
        "equal row values, SQL aliases, empty rule candidates and passing responses do not prove that a repeated business read can be omitted".into(),
    ]
}

pub(super) fn next_step(facts: &Value) -> String {
    let mut step = "Start with the largest endpoint cluster. Execute representative_dependencies_command when present to summarize that case's dependency targets, then select a returned detail_command before proving request or process ownership and response causality in source code.".to_string();
    if unused_clusters(facts).next().is_some() {
        step.push_str(" For unused MySQL calls, follow mysql_unused_diagnosis.source_checks before choosing a rule or reporting an engine gap; include implicit ORM refreshes in the source trace.");
    }
    step
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::evidence::{QUERY_DIRTY_CLUSTERS, rule_guidance};
    use crate::rewrite::model::RewriteIssueKind;
    use std::path::Path;

    #[test]
    fn unused_read_guidance_preserves_uncertainty_and_does_not_offer_a_time_fix() {
        let mut facts = json!({
            "clusters": [{"cluster_id":"unused", "protocol":"mysql", "reason":"unused_recorded", "operations":{"COM_QUERY":1}}],
            "dependency_request_candidates":[], "dynamic_capture_candidates":[]
        });
        let recorded_clusters = facts["clusters"].clone();
        attach(&mut facts);
        assert_eq!(facts["clusters"], recorded_clusters);
        let diagnosis = &facts["mysql_unused_diagnosis"];
        assert_eq!(diagnosis["cluster_ids"], json!(["unused"]));
        assert_eq!(diagnosis["ownership"], "unresolved");
        assert_eq!(diagnosis["observation"], "recorded_calls_not_consumed");
        assert!(!limitations(&facts).is_empty());
        assert!(next_step(&facts).contains("mysql_unused_diagnosis.source_checks"));
        for kind in [
            RewriteIssueKind::Replay,
            RewriteIssueKind::Dependency,
            RewriteIssueKind::Response,
        ] {
            let planners = rule_guidance::applicable_rule_planners(
                Path::new("/target"),
                kind,
                QUERY_DIRTY_CLUSTERS,
                &facts,
                "current",
            );
            assert!(planners.iter().all(|p| p.capability != "mysql_sql_time"));
        }
        let hints = rule_guidance::rule_hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &facts);
        let hint = hints
            .iter()
            .find(|h| h.rule == "mysql-api-triggered")
            .unwrap();
        assert!(hint.hint.contains("not evidence of process ownership"));
    }

    #[test]
    fn mysql_guidance_is_scoped_without_hiding_other_dirty_reasons() {
        for cluster in [
            json!({"protocol":"mysql", "reason":"unmatched_target"}),
            json!({"protocol":"redis", "reason":"unused_recorded"}),
        ] {
            let mut facts = json!({"clusters":[cluster]});
            let original = facts.clone();
            attach(&mut facts);
            assert_eq!(facts, original);
            assert!(limitations(&facts).is_empty());
            assert!(!next_step(&facts).contains("mysql_unused_diagnosis"));
        }
        let mut facts = json!({"clusters":[
            {"cluster_id":"unused", "protocol":"mysql", "reason":"unused_recorded"},
            {"cluster_id":"unmatched", "protocol":"mysql", "reason":"unmatched_target"}
        ]});
        attach(&mut facts);
        assert_eq!(
            facts["mysql_unused_diagnosis"]["cluster_ids"],
            json!(["unused"])
        );
        let planners = rule_guidance::applicable_rule_planners(
            Path::new("/target"),
            RewriteIssueKind::Replay,
            QUERY_DIRTY_CLUSTERS,
            &facts,
            "current",
        );
        assert!(planners.iter().any(|p| p.capability == "mysql_sql_time"));
    }
}
