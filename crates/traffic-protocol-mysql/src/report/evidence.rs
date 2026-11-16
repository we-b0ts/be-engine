//! MySQL report layouts and bounded native diagnostic signatures.
use serde_json::{Value, json};
use traffic_protocol::report::{
    ReportCodec,
    diagnostics::{Diagnosis, DiagnosticSchema, Direction, Field},
};

pub struct EvidenceCodec;
impl ReportCodec for EvidenceCodec {
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
    fn diagnose(&self, facts: &Value) -> Diagnosis {
        super::guidance::diagnose(facts)
    }
    fn has_value_difference(&self, facts: &Value) -> bool {
        super::guidance::has_sql_mismatch(facts)
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
