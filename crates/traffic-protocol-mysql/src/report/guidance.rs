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

fn recorded_transaction_control(cluster: &Value) -> bool {
    let signature = &cluster["representative"]["difference"]["expected"]["signature"];
    let sql = signature["sql"].as_str().or_else(|| {
        (signature["sql_summary"]["truncated"] == false)
            .then(|| signature["sql_summary"]["preview"].as_str())
            .flatten()
    });
    cluster["reason"] == "unused_recorded"
        && sql.is_some_and(|sql| {
            crate::autocommit::assignment(sql) == Some(false)
                || matches!(crate::sql::normalize(sql).as_str(), "commit" | "rollback")
        })
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

fn attach(facts: &mut Value) {
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
            (diagnostic.is_some() || recorded_transaction_control(cluster)).then(|| {
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
                        || recorded_transaction_control(cluster))
            });
        facts["mysql_autocommit_diagnosis"] = json!({
            "observation":"source_transaction_coverage_not_satisfied",
            "clusters":autocommit,
            "source_checks":[
                "Inspect the complete Source connection, query sequence and before/after transaction status. A session AUTOCOMMIT=0 assignment persists after COMMIT; identify every complete affected transaction rather than inferring transaction boundaries from HTTP responses or driver names.",
                "If source_proof_status is incomplete, follow source_proof_rejection.failure_query_sequence and missing_query_sequences (bounded with omitted_missing_query_sequences). Write count and Target status are unknown unless independently present; an unregistered end is not evidence that Target needs BEGIN. Resolve the Source proof first. An original Global ordinary complete read may bridge a pre-write sequence gap only with the same wire connection, identity and continuous status; it retains its Global ownership and consumption requirement. Unknown gaps, unsupported reads and gaps after the first write remain strict. A historical null transaction_evidence likewise proves no write count or Target status.",
                "Read source_transactions.write_count, first_write_query_sequence, last_query_sequence and end. Writes count SQL executions, including an UPDATE affecting zero rows. For the single-UPDATE rollback exception, inspect single_update_outcome, source_error_code, source_affected_rows and autocommit_eligible; do not infer the application's branch condition. If strict_source_effects is true, write_count counts only recognized DML and does not prove other statements are read-only; retain the full Source transaction. Missing status, active sequence gaps, failures and cross-file fragments do not prove a complete transaction; do not fabricate a write interval from a partial recording."
            ],
            "target_checks":[
                "For two or more ordinary Source writes, use the ordinary SQLx transaction API (or the project's with_transaction wrapper) to pin one connection from the FIRST WRITE through the matching COMMIT or ROLLBACK. Include every intervening and trailing query through that end. Prefix ordinary reads may run outside the transaction or on a replica; they must still match and consume their finite Source calls. Explicit Source BEGIN and strict_source_effects retain the full Source boundary.",
                "For exactly one ordinary Source write ending in successful COMMIT, that COMMIT may be omitted after successful delivery on a Target socket with AUTOCOMMIT=1 and no active transaction. For exactly one ordinary UPDATE ending in successful ROLLBACK, the same Target condition permits omission only when Source UPDATE returned an SQL error or succeeded with affected_rows=0, and the corresponding result was delivered. A successful UPDATE with affected_rows>0 followed by ROLLBACK requires a real transaction to undo the write. An UPDATE error is distinct from ROLLBACK itself failing; failed end controls remain strict.",
                "Inspect target_status_before/after: (status & 0x0003) must equal 0x0002. An explicit Target BEGIN disables the single-write exception even while autocommit is enabled. UPDATE executions with affected_rows=0 still count as writes in multi-write transactions. The bounded single-UPDATE exception is a compatibility rule, not proof that arbitrary triggers or stored routines have no effects, and SQL observations do not identify which Source business branch ran. Independent no-op cleanup requires Source proof of an inactive connection or a complete ordinary read-only transaction. No regression.yaml switch or literal SET is required.",
                "Check transaction_evidence.reason, required_operation_count, covered_transaction_count, target_connection_id and target_transaction_id. Compare ordered Source members with Target matched-query references. Missing BEGIN, split/merged transactions, another socket's end, early commit and missing suffix reads do not satisfy a multi-write transaction. A later COMMIT through a pool does not prove coverage.",
                "When member_comparison is present, inspect first_difference before concluding that a remaining COMMIT was omitted. expected and actual are matched Source references in actual Target delivery order, identified by recorded_index, source_connection_id and source_query_sequence; member_position is not a Target event index. A reordered earlier write can prevent selection of the expected end even after every business statement was consumed. The two member prefixes are bounded with omitted counts, while first_difference can identify a later position. Historical reports without this comparison do not establish the delivered order.",
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

fn limitations(facts: &Value) -> Vec<String> {
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

fn next_step(facts: &Value) -> String {
    let mut step = String::new();
    if facts.get("mysql_autocommit_diagnosis").is_some() {
        step.push_str("For MySQL transaction evidence, follow mysql_autocommit_diagnosis: resolve an incomplete Source proof using its rejected query references first; otherwise inspect Source write count and first-write-through-end members, then the actual Target socket's transaction status, missing members and member_comparison.first_difference before changing code or alleging an engine gap.");
    } else if unused_clusters(facts).next().is_some() {
        step.push_str("For unused MySQL calls, follow mysql_unused_diagnosis.source_checks before choosing a rule or reporting an engine gap; include implicit ORM refreshes in the source trace.");
    }
    step
}

pub(super) fn diagnose(facts: &Value) -> traffic_protocol::report::diagnostics::Diagnosis {
    let mut native = json!({"clusters":facts["clusters"]});
    attach(&mut native);
    let limitations = limitations(&native);
    let step = next_step(&native);
    let mut details = native
        .as_object()
        .expect("native diagnosis is an object")
        .clone();
    details.remove("clusters");
    traffic_protocol::report::diagnostics::Diagnosis {
        details,
        limitations,
        next_steps: if step.is_empty() {
            Vec::new()
        } else {
            vec![step]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn historical_unused_ends_get_guidance_without_inventing_a_write_interval() {
        for sql in ["COMMIT", "ROLLBACK"] {
            let mut facts = json!({"clusters":[{
                "cluster_id":"end", "protocol":"mysql", "reason":"unused_recorded", "count":1,
                "representative":{"difference":{"expected":{"signature":{
                    "connection_id":"source", "query_sequence":91,
                    "sql_summary":{"preview":sql, "truncated":false}
                }}}}
            }]});
            attach(&mut facts);
            let evidence = &facts["mysql_autocommit_diagnosis"]["clusters"][0];
            assert_eq!(evidence["query_sequence"], 91);
            assert!(evidence["transaction_evidence"].is_null());
            assert!(
                facts["mysql_autocommit_diagnosis"]["source_checks"]
                    .to_string()
                    .contains("historical null")
            );
            assert!(
                facts["mysql_unused_diagnosis"]["source_checks"]
                    .to_string()
                    .contains("Source proof")
            );
            assert!(
                facts["mysql_autocommit_diagnosis"]["required_behavior"]
                    .to_string()
                    .contains("without wrapping prefix reads")
            );
        }
    }

    #[test]
    fn a_truncated_end_preview_cannot_establish_a_transaction_control() {
        for (sql, truncated) in [("COMMIT", true), ("ROLLBACK TO SAVEPOINT example", false)] {
            let mut facts = json!({"clusters":[{
                "cluster_id":"unknown", "protocol":"mysql", "reason":"unused_recorded", "count":1,
                "representative":{"difference":{"expected":{"signature":{
                    "sql_summary":{"preview":sql, "truncated":truncated}
                }}}}
            }]});
            attach(&mut facts);
            assert!(facts.get("mysql_autocommit_diagnosis").is_none());
        }
    }

    #[test]
    fn a_rejected_source_end_guides_proof_repair_without_fabricating_target_evidence() {
        let rejected = json!({
            "kind":"mysql_autocommit_transaction_coverage", "reason":"source_sequence_gap",
            "source_proof_status":"incomplete",
            "source_proof_rejection":{"failure_query_sequence":90,
                "missing_query_sequences":[89], "omitted_missing_query_sequences":0},
            "source_transactions":[{"source_connection_id":"source", "last_query_sequence":91,
                "end":"commit"}]
        });
        let mut facts = json!({"clusters":[{
            "cluster_id":"rejected", "protocol":"mysql", "reason":"unused_recorded", "count":1,
            "representative":{"difference":{"expected":{"signature":{"diagnostic":rejected}}}}
        }]});
        attach(&mut facts);
        let cluster = &facts["mysql_autocommit_diagnosis"]["clusters"][0];
        assert_eq!(cluster["connection_id"], "source");
        assert_eq!(cluster["query_sequence"], 91);
        assert_eq!(cluster["transaction_evidence"], rejected);
        let checks = facts["mysql_autocommit_diagnosis"]["source_checks"].to_string();
        for text in [
            "Source proof first",
            "unknown",
            "Global ownership",
            "after the first write",
        ] {
            assert!(checks.contains(text), "missing {text}");
        }
        assert!(next_step(&facts).contains("rejected query references first"));
        assert!(
            cluster["transaction_evidence"]["source_transactions"][0]
                .get("write_count")
                .is_none()
        );
        assert!(
            cluster["transaction_evidence"]["source_transactions"][0]
                .get("target_status_before")
                .is_none()
        );
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
