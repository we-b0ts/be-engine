//! Historical HTTP report locations and header observations.
use serde_json::{Value, json};
use traffic_protocol::report::{
    ReportCodec,
    diagnostics::{DiagnosticSchema, Difference, Direction, Field, Observation},
};

pub struct EvidenceCodec;
impl ReportCodec for EvidenceCodec {
    fn validate_legacy_session(&self, report: &Value, _: &str) -> anyhow::Result<Option<usize>> {
        use traffic_protocol::report::validation::{array, empty, number};
        let fields = [
            "unmatched_http_requests",
            "unsupported_http_exchanges",
            "http_request_header_mismatches",
            "unused_case_http_exchanges",
            "unused_global_http_exchanges",
        ];
        if !fields
            .iter()
            .chain([&"unused_global_http_exchange_count", &"http_ingress"])
            .any(|field| report.get(*field).is_some())
        {
            return Ok(None);
        }
        empty(report, &fields)?;
        let ingress = &report["http_ingress"];
        anyhow::ensure!(
            number(ingress, "omitted")? == 0
                && number(ingress, "pending")? == 0
                && array(ingress, "observations")?
                    .iter()
                    .all(|observation| observation["status"] == "body_complete"),
            "actual HTTP request ingress remains incomplete or cancelled"
        );
        Ok(Some(usize::try_from(number(
            report,
            "unused_global_http_exchange_count",
        )?)?))
    }
    fn diagnostics(&self) -> &dyn DiagnosticSchema {
        self
    }
    fn unused_case_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["unused_case_http_exchanges"]
    }
    fn reclassified_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["unused_global_http_exchanges"]
    }
    fn supports_source_occurrences(&self) -> bool {
        false
    }
}
impl DiagnosticSchema for EvidenceCodec {
    fn section<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        report
    }
    fn fields(&self) -> &'static [Field] {
        &[
            Field {
                name: "http_request_header_mismatches",
                reason: "request_header_mismatch",
                direction: Direction::Paired,
                label: Some("header"),
            },
            Field {
                name: "unmatched_http_requests",
                reason: "unmatched_target",
                direction: Direction::TargetOnly,
                label: None,
            },
            Field {
                name: "unsupported_http_exchanges",
                reason: "unsupported_target",
                direction: Direction::TargetOnly,
                label: None,
            },
            Field {
                name: "unused_case_http_exchanges",
                reason: "unused_recorded",
                direction: Direction::UnusedRecorded,
                label: None,
            },
        ]
    }
    fn matched_rows<'a>(&self, report: &'a Value, _: &str) -> &'a Value {
        &report["matched_http_exchanges"]
    }
    fn additional_dirty(&self, report: &Value) -> bool {
        report.get("http_ingress").is_some_and(|ingress| {
            ingress["pending"].as_u64().is_none_or(|n| n > 0)
                || ingress["omitted"].as_u64().is_none_or(|n| n > 0)
                || ingress["observations"]
                    .as_array()
                    .is_none_or(|observations| {
                        observations.iter().any(|o| o["status"] != "body_complete")
                    })
        })
    }
    fn operation(&self, event: &Value) -> String {
        let parts = ["command", "method", "operation", "topic", "uri"]
            .into_iter()
            .filter_map(|field| event[field].as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if parts.is_empty() {
            "unknown".into()
        } else {
            parts
        }
    }
    fn signature(&self, event: &Value) -> Value {
        let mut signature = traffic_protocol::report::diagnostics::STANDARD.signature(event);
        if let Some(uri) = event.get("uri") {
            signature["uri"] = uri.clone();
        }
        signature
    }
    fn paired_difference(&self, event: &Value) -> Option<Difference> {
        let observation = |side: &str| {
            let value = &event[side];
            Observation {
                presence: value["presence"].as_str().unwrap_or("unavailable").into(),
                signature: Some(json!({
                    "header":event.get("header"), "method":event.get("method"),
                    "uri":event.get("uri"), "values":value.get("values"),
                    "protected":value.get("protected"), "comparison":event.get("comparison"),
                    "rule_id":event.get("rule_id"), "validation_error":event.get("validation_error"),
                    "request_started_at":event.get(if side == "expected" {
                        "source_request_started_at"
                    } else {"target_request_started_at"})
                })),
            }
        };
        Some(Difference {
            kind: event["kind"].as_str().unwrap_or("header_mismatch").into(),
            expected: observation("expected"),
            actual: observation("actual"),
        })
    }
}
