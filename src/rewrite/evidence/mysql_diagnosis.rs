//! Investigation guidance for MySQL consumption and transaction evidence.
use serde_json::{Value, json};

fn unused_clusters(facts: &Value) -> impl Iterator<Item = &Value> {
    facts["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|cluster| cluster["protocol"] == "mysql" && cluster["reason"] == "unused_recorded")
}

fn signatures(cluster: &Value) -> impl Iterator<Item = &Value> {
    ["expected", "actual"]
        .into_iter()
        .map(|side| &cluster["representative"]["difference"][side]["signature"])
}

fn transaction_diagnostic(cluster: &Value) -> Option<&Value> {
    signatures(cluster)
        .map(|signature| &signature["diagnostic"])
        .find(|diagnostic| diagnostic["kind"] == "mysql_autocommit_transaction_coverage")
}

fn recorded_autocommit_off(cluster: &Value) -> bool {
    let signature = &cluster["representative"]["difference"]["expected"]["signature"];
    let sql = signature["sql"].as_str().or_else(|| {
        (signature["sql_summary"]["truncated"] == false)
            .then(|| signature["sql_summary"]["preview"].as_str())
            .flatten()
    });
    cluster["reason"] == "unused_recorded"
        && sql.and_then(crate::mysql::autocommit::assignment) == Some(false)
}

// A transaction-only witness cannot justify a generated SQL-value rule. A
// multi-event cluster's representative does not classify its other events.
pub(super) fn has_sql_mismatch(facts: &Value) -> bool {
    facts["clusters"].as_array().is_some_and(|clusters| {
        clusters.iter().any(|cluster| {
            cluster["protocol"] == "mysql"
                && cluster["reason"] == "unmatched_target"
                && (transaction_diagnostic(cluster).is_none()
                    || cluster["count"].as_u64().is_some_and(|count| count > 1))
        })
    })
}

pub(super) fn attach(facts: &mut Value) {
    let cluster_ids: Vec<_> = unused_clusters(facts)
        .filter_map(|cluster| cluster["cluster_id"].as_str().map(str::to_owned))
        .collect();
    if unused_clusters(facts).next().is_some() {
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
    let autocommit: Vec<_> = facts["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|cluster| cluster["protocol"] == "mysql")
        .filter_map(|cluster| {
            let signature = &cluster["representative"]["difference"]["expected"]["signature"];
            let diagnostic = transaction_diagnostic(cluster);
            let interval = diagnostic.map(|diagnostic| &diagnostic["source_transactions"][0]);
            let connection = signature
                .get("connection_id")
                .filter(|value| !value.is_null())
                .or_else(|| interval.and_then(|interval| interval.get("source_connection_id")));
            let sequence = signature
                .get("query_sequence")
                .filter(|value| !value.is_null())
                .or_else(|| interval.and_then(|interval| interval.get("last_query_sequence")));
            (diagnostic.is_some() || recorded_autocommit_off(cluster)).then(|| {
                json!({"cluster_id":cluster["cluster_id"],
                    "reason":cluster["reason"],
                    "connection_id":connection,
                    "query_sequence":sequence,
                    "transaction_evidence":diagnostic})
            })
        })
        .collect();
    if !autocommit.is_empty() {
        let only_autocommit = unused_clusters(facts).next().is_some()
            && unused_clusters(facts).all(|cluster| {
                cluster["count"] == 1
                    && (transaction_diagnostic(cluster).is_some()
                        || recorded_autocommit_off(cluster))
            });
        facts["mysql_autocommit_diagnosis"] = json!({
            "observation":"source_transaction_coverage_not_satisfied",
            "clusters":autocommit,
            "source_checks":[
                "Inspect the complete Source connection, query sequence and before/after transaction status. A session AUTOCOMMIT=0 assignment persists after COMMIT; identify every complete affected transaction rather than inferring transaction boundaries from HTTP responses or driver names.",
                "Read source_transactions.write_count, first_write_query_sequence, last_query_sequence and end. Writes count SQL executions, including an UPDATE affecting zero rows. For the single-UPDATE rollback exception, inspect single_update_outcome, source_error_code, source_affected_rows and autocommit_eligible; do not infer the application's branch condition. If strict_source_effects is true, write_count counts only recognized DML and does not prove other statements are read-only; retain the full Source transaction. Missing status, active sequence gaps, failures and cross-file fragments do not prove a complete transaction; do not fabricate a write interval from a partial recording."
            ],
            "target_checks":[
                "For two or more ordinary Source writes, use the ordinary SQLx transaction API (or the project's with_transaction wrapper) to pin one connection from the FIRST WRITE through the matching COMMIT or ROLLBACK. Include every intervening and trailing query through that end. Prefix ordinary reads may run outside the transaction or on a replica; they must still match and consume their finite Source calls. Explicit Source BEGIN and strict_source_effects retain the full Source boundary.",
                "For exactly one ordinary Source write ending in successful COMMIT, that COMMIT may be omitted after successful delivery on a Target socket with AUTOCOMMIT=1 and no active transaction. For exactly one ordinary UPDATE ending in successful ROLLBACK, the same Target condition permits omission only when Source UPDATE returned an SQL error or succeeded with affected_rows=0, and the corresponding result was delivered. A successful UPDATE with affected_rows>0 followed by ROLLBACK requires a real transaction to undo the write. An UPDATE error is distinct from ROLLBACK itself failing; failed end controls remain strict.",
                "Inspect target_status_before/after: (status & 0x0003) must equal 0x0002. An explicit Target BEGIN disables the single-write exception even while autocommit is enabled. UPDATE executions with affected_rows=0 still count as writes in multi-write transactions. The bounded single-UPDATE exception is a compatibility rule, not proof that arbitrary triggers or stored routines have no effects, and SQL observations do not identify which Source business branch ran. Independent no-op cleanup requires Source proof of an inactive connection or a complete ordinary read-only transaction. No regression.yaml switch or literal SET is required.",
                "Check transaction_evidence.reason, required_operation_count, covered_transaction_count, target_connection_id and target_transaction_id. Compare ordered Source members with Target matched-query references. Missing BEGIN, split/merged transactions, another socket's end, early commit and missing suffix reads do not satisfy a multi-write transaction. A later COMMIT through a pool does not prove coverage.",
                "If complete independent Target transaction evidence is unavailable, retain an unresolved diagnosis. If a complete supported pair still remains dirty, investigate Replay coverage and report publication with the exact transaction references."
            ],
            "required_behavior":"Repair the evidenced transaction interval without wrapping prefix reads solely for Replay. Do not disable autocommit on a shared pool, drop business SELECTs, skip the API or use a generated-value rule to hide transaction membership failures. A positive-row UPDATE followed by business ROLLBACK, multiple writes and failed transaction-control observations remain strict. Passing HTTP responses alone do not prove coverage."
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
    let mut limitations = Vec::new();
    if unused_clusters(facts).next().is_some() {
        limitations.extend([
            "unused_recorded means a recorded MySQL call was not consumed; it does not by itself prove an SQL matching defect, optional read or engine capability gap".into(),
            "equal row values, SQL aliases, empty rule candidates and passing responses do not prove that a repeated business read can be omitted".into(),
        ]);
    }
    if facts.get("mysql_autocommit_diagnosis").is_some() {
        limitations.push("SQL matching alone does not prove transaction coverage; use actual Target connection/status witnesses and the complete Source first-write-through-end interval. A missing historical witness remains unknown.".into());
    }
    limitations
}

pub(super) fn next_step(facts: &Value) -> String {
    let mut step = "Start with the largest endpoint cluster. Execute representative_dependencies_command when present to summarize that case's dependency targets, then select a returned detail_command before proving request or process ownership and response causality in source code.".to_string();
    if facts.get("mysql_autocommit_diagnosis").is_some() {
        step.push_str(" For MySQL transaction evidence, follow mysql_autocommit_diagnosis: inspect Source write count and first-write-through-end members, then the actual Target socket's transaction status and missing members before changing code or alleging an engine gap.");
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

    #[test]
    fn unmatched_transaction_evidence_guides_the_write_interval_without_value_rules() {
        let cluster = json!({
            "cluster_id":"transaction", "protocol":"mysql", "reason":"unmatched_target", "count":1,
            "representative":{"difference":{"actual":{"signature":{
                "diagnostic":{"kind":"mysql_autocommit_transaction_coverage",
                    "reason":"target_transaction_members_or_end_differ",
                    "source_transactions":[{"write_count":2,"source_connection_id":"source-connection","first_write_query_sequence":5,
                        "last_query_sequence":9,"required_operation_count":4,"end":"commit",
                        "target_status_before":2,"target_status_after":2}]}
            }}}}
        });
        let mut facts = json!({"clusters":[cluster.clone()]});
        attach(&mut facts);
        assert_eq!(facts["clusters"], json!([cluster]));
        assert!(facts.get("mysql_unused_diagnosis").is_none());
        let diagnosis = &facts["mysql_autocommit_diagnosis"];
        assert_eq!(
            diagnosis["clusters"][0]["transaction_evidence"]["source_transactions"][0]["write_count"],
            2
        );
        assert_eq!(
            diagnosis["clusters"][0]["connection_id"],
            "source-connection"
        );
        assert_eq!(diagnosis["clusters"][0]["query_sequence"], 9);
        let checks = diagnosis["target_checks"].to_string();
        for text in [
            "FIRST WRITE",
            "trailing",
            "Prefix",
            "0x0002",
            "with_transaction",
        ] {
            assert!(checks.contains(text), "missing {text}");
        }
        for text in [
            "affected_rows=0",
            "affected_rows>0",
            "UPDATE error",
            "failed end controls",
        ] {
            assert!(
                checks.contains(text),
                "missing single-UPDATE guidance: {text}"
            );
        }
        assert!(
            diagnosis["source_checks"]
                .to_string()
                .contains("autocommit_eligible")
        );
        assert!(!limitations(&facts).is_empty());
        assert!(next_step(&facts).contains("first-write-through-end"));
        let planners = rule_guidance::applicable_rule_planners(
            Path::new("/target"),
            RewriteIssueKind::Replay,
            QUERY_DIRTY_CLUSTERS,
            &facts,
            "current",
        );
        assert!(planners.iter().all(|planner| !matches!(
            planner.capability.as_str(),
            "mysql_sql_time" | "dynamic_value"
        )));
        // A distinct SQL mismatch still needs its ordinary rule discovery.
        facts["clusters"].as_array_mut().unwrap().push(json!({
            "protocol":"mysql", "reason":"unmatched_target", "count":1,
            "representative":{"difference":{"actual":{"signature":{"sql":"SELECT 1"}}}}
        }));
        assert!(has_sql_mismatch(&facts));
        facts["clusters"].as_array_mut().unwrap().pop();
        facts["clusters"][0]["count"] = json!(2);
        assert!(has_sql_mismatch(&facts));
    }

    #[test]
    fn unmatched_transaction_does_not_overwrite_unused_read_guidance() {
        let mut facts = json!({"clusters":[
            {"cluster_id":"read", "protocol":"mysql", "reason":"unused_recorded", "count":1},
            {"cluster_id":"transaction", "protocol":"mysql", "reason":"unmatched_target", "count":1,
                "representative":{"difference":{"actual":{"signature":{"diagnostic":{
                    "kind":"mysql_autocommit_transaction_coverage", "reason":"target_transaction_missing"
                }}}}}}
        ]});
        attach(&mut facts);
        assert!(facts["mysql_autocommit_diagnosis"].is_object());
        assert!(
            facts["mysql_unused_diagnosis"]["source_checks"]
                .to_string()
                .contains("ORM")
        );
        assert!(
            facts["mysql_unused_diagnosis"]["required_behavior"]
                .to_string()
                .contains("Business SELECTs")
        );
    }
}
