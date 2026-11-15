//! Built-in evidence formats for the protocol-independent report collector.
use super::Builtin;
use serde_json::Value;
use traffic_protocol::report::diagnostics::{
    DiagnosticSchema, Difference, Direction, Field, Observation,
};

const MYSQL_EVENTS: &[Field] = &[
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
];

const HTTP_EVENTS: &[Field] = &[
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
];

impl DiagnosticSchema for Builtin {
    fn section<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        match self.0 {
            "mysql" | "http" => report,
            _ => &report[protocol],
        }
    }
    fn fields(&self) -> &'static [Field] {
        match self.0 {
            "mysql" => MYSQL_EVENTS,
            "http" => HTTP_EVENTS,
            _ => traffic_protocol::report::diagnostics::STANDARD.fields(),
        }
    }
    fn matched_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        match self.0 {
            "mysql" => &report["matched_queries"],
            "http" => &report["matched_http_exchanges"],
            _ => &report[protocol]["matched"],
        }
    }
    fn additional_dirty(&self, report: &Value) -> bool {
        self.0 == "http"
            && report.get("http_ingress").is_some_and(|ingress| {
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
        let mut parts = Vec::new();
        for field in ["command", "method", "operation", "topic"] {
            if let Some(value) = event.get(field).and_then(Value::as_str) {
                parts.push(value);
            }
        }
        if let Some(uri) = event.get("uri").and_then(Value::as_str) {
            parts.push(uri);
        }
        if parts.is_empty() {
            "unknown".to_string()
        } else {
            parts.join(" ")
        }
    }

    fn signature(&self, event: &Value) -> Value {
        let mut signature = serde_json::Map::new();
        for field in [
            "command",
            "method",
            "uri",
            "operation",
            "topic",
            "database",
            "sql",
            "sql_summary",
            "index",
            "connection_id",
            "query_sequence",
            "row_count",
            "status",
            "reason",
            "diagnostic",
            "target_event_index",
            "failure_kind",
            "client_outcome",
            "duration_ms",
        ] {
            if let Some(value) = event.get(field) {
                signature.insert(field.to_string(), value.clone());
            }
        }
        // Target query reports carry the original SQL, unlike Source inventory
        // rows, which already carry a summary. Derive the diagnostic before the
        // public signature truncates SQL to its projection-only prefix.
        if !signature.contains_key("sql_summary")
            && let Some(sql) = event.get("sql").and_then(Value::as_str)
        {
            signature.insert(
                "sql_summary".into(),
                serde_json::json!(traffic_protocol_mysql::report::SqlSummary::new(sql)),
            );
        }
        Value::Object(signature)
    }

    fn paired_difference(&self, event: &Value) -> Option<Difference> {
        if self.0 != "http" {
            return None;
        }
        let observation = |side: &str| {
            let value = &event[side];
            Observation {
                presence: value
                    .get("presence")
                    .and_then(Value::as_str)
                    .unwrap_or("unavailable")
                    .to_string(),
                signature: Some(serde_json::json!({
                    "header": event.get("header"),
                    "method": event.get("method"),
                    "uri": event.get("uri"),
                    "values": value.get("values"),
                    "protected": value.get("protected"),
                    "comparison": event.get("comparison"),
                    "rule_id": event.get("rule_id"),
                    "validation_error": event.get("validation_error"),
                    "request_started_at": event.get(if side == "expected" { "source_request_started_at" } else { "target_request_started_at" }),
                })),
            }
        };
        Some(Difference {
            kind: event
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("header_mismatch")
                .to_string(),
            expected: observation("expected"),
            actual: observation("actual"),
        })
    }
    fn fingerprint(&self, event: &Value) -> Option<String> {
        event
            .get("sql")
            .and_then(Value::as_str)
            .map(|sql| crate::replay::report::fnv1a64(sql.as_bytes()))
    }
}
