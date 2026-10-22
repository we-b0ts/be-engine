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
    let autocommit: Vec<_> = unused_clusters(facts)
        .filter_map(|cluster| {
            let signature = &cluster["representative"]["difference"]["expected"]["signature"];
            let diagnostic = &signature["diagnostic"];
            let sql = signature["sql"].as_str().or_else(|| {
                (signature["sql_summary"]["truncated"] == false)
                    .then(|| signature["sql_summary"]["preview"].as_str())
                    .flatten()
            });
            (diagnostic["kind"] == "mysql_autocommit_transaction_coverage"
                || sql.and_then(crate::mysql::autocommit::assignment) == Some(false))
            .then(|| {
                json!({"cluster_id":cluster["cluster_id"],
                    "connection_id":signature["connection_id"],
                    "query_sequence":signature["query_sequence"],
                    "transaction_evidence":diagnostic})
            })
        })
        .collect();
    if !autocommit.is_empty() {
        let only_autocommit = autocommit.len() == cluster_ids.len()
            && unused_clusters(facts).all(|cluster| cluster["count"] == 1);
        facts["mysql_autocommit_diagnosis"] = json!({
            "observation":"recorded_autocommit_off_not_satisfied",
            "clusters":autocommit,
            "source_checks":[
                "Inspect the complete Source connection, query sequence and before/after transaction status. A session AUTOCOMMIT=0 assignment persists after COMMIT; identify every complete affected transaction rather than inferring transaction boundaries from HTTP responses or driver names.",
                "Trace Source callers to establish transaction settings and the full read/write scope. Missing status, active sequence gaps, failures, unsupported statements and cross-file fragments do not prove a complete transaction."
            ],
            "target_checks":[
                "Use the ordinary SQLx transaction API (or the project's with_transaction wrapper) to pin one connection for BEGIN, every corresponding SELECT/write, and the matching COMMIT or ROLLBACK. A later COMMIT issued through a pool does not prove transaction coverage.",
                "Check transaction_evidence.reason and covered_transaction_count. Replay accepts complete ordered implicit/explicit transaction pairs after successful delivery. Missing BEGIN, split/merged transactions, another connection's end, early commits and incomplete coverage retain this SET requirement.",
                "If complete independent Target transaction evidence is unavailable, retain an unresolved diagnosis. If a complete supported pair still remains dirty, investigate Replay coverage and report publication with the exact transaction references."
            ],
            "required_behavior":"Verify transaction equivalence; do not add a literal SET solely to satisfy Replay, disable autocommit on a shared pool, skip the API, or infer an engine gap from passing responses. Matching, finite business calls and commit/rollback outcomes remain required."
        });
        if only_autocommit {
            facts["mysql_unused_diagnosis"]["source_checks"] =
                facts["mysql_autocommit_diagnosis"]["source_checks"].clone();
            facts["mysql_unused_diagnosis"]["required_behavior"] =
                facts["mysql_autocommit_diagnosis"]["required_behavior"].clone();
        }
    }
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
    if facts.get("mysql_autocommit_diagnosis").is_some() {
        step.push_str(" For unconsumed AUTOCOMMIT=0, follow mysql_autocommit_diagnosis and inspect exact Source/Target transaction coverage before changing Target code or alleging an engine gap.");
    } else if unused_clusters(facts).next().is_some() {
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
            .find(|h| h.capability == "api_triggered_process_traffic")
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

    #[test]
    fn autocommit_guidance_uses_transaction_evidence_without_inferring_a_gap() {
        let mut facts = json!({"clusters":[{
            "cluster_id":"setup", "protocol":"mysql", "reason":"unused_recorded", "count":1,
            "representative":{"difference":{"expected":{"signature":{
                "connection_id":"source-connection", "query_sequence":3,
                "sql_summary":{"preview":"SET AUTOCOMMIT = 0", "truncated":false},
                "diagnostic":{"kind":"mysql_autocommit_transaction_coverage",
                    "reason":"target_transaction_missing", "covered_transaction_count":0,
                    "source_transactions":[{"first_query_sequence":5,"last_query_sequence":7,"end":"commit"}]}
            }}}}
        }]});
        let original = facts["clusters"].clone();
        attach(&mut facts);
        assert_eq!(facts["clusters"], original);
        let diagnosis = &facts["mysql_autocommit_diagnosis"];
        assert_eq!(
            diagnosis["clusters"][0]["transaction_evidence"]["reason"],
            "target_transaction_missing"
        );
        assert!(
            diagnosis["target_checks"]
                .to_string()
                .contains("with_transaction")
        );
        assert!(
            !facts["mysql_unused_diagnosis"]["source_checks"]
                .to_string()
                .contains("ORM")
        );
        assert!(next_step(&facts).contains("mysql_autocommit_diagnosis"));
        assert_eq!(facts["mysql_unused_diagnosis"]["ownership"], "unresolved");
    }

    #[test]
    fn historical_setup_reports_get_guidance_without_fabricated_transaction_proof() {
        let mut facts = json!({"clusters":[{
            "cluster_id":"setup", "protocol":"mysql", "reason":"unused_recorded", "count":2,
            "representative":{"difference":{"expected":{"signature":{
                "sql_summary":{"preview":"SET AUTOCOMMIT = 0", "truncated":false}
            }}}}
        }]});
        attach(&mut facts);
        assert!(
            facts["mysql_autocommit_diagnosis"]["clusters"][0]["transaction_evidence"].is_null()
        );
        // One representative cannot classify the other calls in a mixed cluster.
        assert!(
            facts["mysql_unused_diagnosis"]["source_checks"]
                .to_string()
                .contains("ORM")
        );
    }
}
