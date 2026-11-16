//! Native report locations and safe diagnostic projections supplied to the host.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Provider-owned interpretation of native evidence. The host retains the
/// original facts, command construction, issue state and publication.
#[derive(Debug, Default)]
pub struct Diagnosis {
    pub details: serde_json::Map<String, Value>,
    pub limitations: Vec<String>,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Provisional,
    UnusedRecorded,
    TargetOnly,
    Paired,
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub reason: &'static str,
    pub direction: Direction,
    pub label: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Difference {
    pub kind: String,
    pub expected: Observation,
    pub actual: Observation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub presence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Value>,
}

const FIELDS: &[Field] = &[
    Field {
        name: "unmatched",
        reason: "unmatched_target",
        direction: Direction::TargetOnly,
        label: None,
    },
    Field {
        name: "unsupported",
        reason: "unsupported_target",
        direction: Direction::TargetOnly,
        label: None,
    },
    Field {
        name: "unsafe_events",
        reason: "unsafe_target",
        direction: Direction::TargetOnly,
        label: None,
    },
    Field {
        name: "unused_case",
        reason: "unused_recorded",
        direction: Direction::UnusedRecorded,
        label: None,
    },
];

pub trait DiagnosticSchema: Send + Sync {
    fn diagnose(&self, _facts: &Value) -> Diagnosis {
        Diagnosis::default()
    }
    fn has_value_difference(&self, _facts: &Value) -> bool {
        false
    }
    fn section<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report["dependency_protocols"][protocol]
    }
    fn fields(&self) -> &'static [Field] {
        FIELDS
    }
    fn matched_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &self.section(report, protocol)["matched"]
    }
    fn additional_dirty(&self, _report: &Value) -> bool {
        false
    }
    fn operation(&self, event: &Value) -> String {
        let parts = ["command", "method", "operation", "topic"]
            .into_iter()
            .filter_map(|field| event[field].as_str())
            .collect::<Vec<_>>();
        if parts.is_empty() {
            "unknown".into()
        } else {
            parts.join(" ")
        }
    }
    fn signature(&self, event: &Value) -> Value {
        let fields = [
            "command",
            "method",
            "operation",
            "topic",
            "database",
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
        ];
        Value::Object(
            fields
                .into_iter()
                .filter_map(|field| event.get(field).map(|value| (field.into(), value.clone())))
                .collect(),
        )
    }
    fn paired_difference(&self, _event: &Value) -> Option<Difference> {
        None
    }
    fn fingerprint(&self, _event: &Value) -> Option<String> {
        None
    }
}

pub struct Standard;
pub static STANDARD: Standard = Standard;
impl DiagnosticSchema for Standard {}
