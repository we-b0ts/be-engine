//! MySQL report layouts and bounded native diagnostic signatures.
use serde_json::{Value, json};
use traffic_protocol::report::{
    ReportCodec,
    diagnostics::{DiagnosticSchema, Direction, Field},
};

pub struct EvidenceCodec;
impl ReportCodec for EvidenceCodec {
    fn validate_legacy_session(&self, report: &Value, _: &str) -> anyhow::Result<Option<usize>> {
        use traffic_protocol::report::validation::{empty, number};
        let fields = [
            "unmatched_queries",
            "unsupported_commands",
            "unused_case_exchanges",
            "unused_global_exchanges",
        ];
        if !fields
            .iter()
            .chain([&"unused_global_exchange_count"])
            .any(|field| report.get(*field).is_some())
        {
            return Ok(None);
        }
        empty(report, &fields)?;
        Ok(Some(usize::try_from(number(
            report,
            "unused_global_exchange_count",
        )?)?))
    }
    fn diagnostics(&self) -> &dyn DiagnosticSchema {
        self
    }
    fn unused_case_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["unused_case_exchanges"]
    }
    fn reclassified_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["unused_global_exchanges"]
    }
}

impl DiagnosticSchema for EvidenceCodec {
    fn has_value_difference(&self, facts: &Value) -> bool {
        facts["clusters"].as_array().is_some_and(|clusters| {
            clusters.iter().any(|cluster| {
                cluster["protocol"] == "mysql"
                    && cluster["reason"] == "unmatched_target"
                    && (!has_transaction_diagnostic(cluster)
                        || cluster["count"].as_u64().is_some_and(|count| count > 1))
            })
        })
    }
    fn section<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        report
    }
    fn fields(&self) -> &'static [Field] {
        &[
            Field {
                name: "unmatched_queries",
                reason: "unmatched_target",
                direction: Direction::TargetOnly,
                label: None,
            },
            Field {
                name: "unsupported_commands",
                reason: "unsupported_target",
                direction: Direction::TargetOnly,
                label: None,
            },
            Field {
                name: "unused_case_exchanges",
                reason: "unused_recorded",
                direction: Direction::UnusedRecorded,
                label: None,
            },
        ]
    }
    fn matched_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["matched_queries"]
    }
    fn signature(&self, event: &Value) -> Value {
        let mut signature = traffic_protocol::report::diagnostics::STANDARD.signature(event);
        for field in ["sql", "sql_summary"] {
            if let Some(value) = event.get(field) {
                signature[field] = value.clone();
            }
        }
        if signature.get("sql_summary").is_none()
            && let Some(sql) = event["sql"].as_str()
        {
            signature["sql_summary"] = json!(super::SqlSummary::new(sql));
        }
        signature
    }
    fn fingerprint(&self, event: &Value) -> Option<String> {
        event["sql"]
            .as_str()
            .map(|sql| super::fnv1a64(sql.as_bytes()))
    }
}

// A transaction-only witness cannot justify a generated SQL-value rule. A
// multi-event cluster's representative does not classify its other events.
fn has_transaction_diagnostic(cluster: &Value) -> bool {
    ["expected", "actual"].into_iter().any(|side| {
        cluster["representative"]["difference"][side]["signature"]["diagnostic"]["kind"]
            == "mysql_autocommit_transaction_coverage"
    })
}
