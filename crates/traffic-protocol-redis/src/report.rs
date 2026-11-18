//! Native subscription identity carried by Source-bound report projections.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub struct EvidenceCodec;
impl traffic_protocol::report::ReportCodec for EvidenceCodec {
    fn validate_legacy_session(&self, report: &Value, protocol: &str) -> Result<Option<usize>> {
        traffic_protocol::report::validation::named_section(report, protocol)
    }
    fn diagnostics(&self) -> &dyn traffic_protocol::report::diagnostics::DiagnosticSchema {
        self
    }
    fn unused_case_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]["unused_case"]
    }
    fn reclassified_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]["unused_global"]
    }
    fn requires_source_exchange_id(&self, row: &Value) -> bool {
        row["command"] == "PUBSUB_PUSH"
    }
}
impl traffic_protocol::report::diagnostics::DiagnosticSchema for EvidenceCodec {
    fn section<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]
    }
    fn matched_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report[protocol]["matched"]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationIdentity {
    pub target: traffic_protocol::connection::Endpoint,
    pub database: i64,
    pub username: Option<String>,
    pub connection_id: Uuid,
    pub subscription_sequence: u64,
    pub kind: String,
    pub subject: Vec<u8>,
    pub subscription_proof: Value,
}

impl NotificationIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.subscription_sequence > 0,
            "invalid shared notification lane"
        );
        ensure!(
            matches!(self.kind.as_str(), "channel" | "pattern" | "shard_channel"),
            "invalid shared notification kind"
        );
        Ok(())
    }
}
