//! Native semantic evidence support, independent of inventory and ownership.
use anyhow::{Context, Result};
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::evidence::{EvidenceAdapter, SourceTiming};
use traffic_protocol::observation::{TrafficInteraction, optional_endpoint};

mod index;

pub struct NativeEvidence;
impl EvidenceAdapter for NativeEvidence {
    fn proof_selector(&self, event: &Value) -> Value {
        index::proof(event)
    }
    fn capture_complete(&self, event: &Value) -> bool {
        index::complete(event)
    }
    fn lookup_projection(
        &self,
        event: &Value,
    ) -> Result<traffic_protocol::evidence::index::IndexProjection> {
        index::lookup(event)
    }
    fn index_projection(
        &self,
        event: &Value,
    ) -> Result<traffic_protocol::evidence::index::IndexProjection> {
        index::project(event)
    }
    fn discovery_annotations(
        &self,
        event: &Value,
        side: traffic_protocol::evidence::MessageSide,
    ) -> Result<serde_json::Map<String, Value>> {
        discovery::annotations(event, side)
    }
    fn query_value(
        &self,
        event: &Value,
        payload: &[u8],
        query: traffic_protocol::evidence::ValueQuery<'_>,
        reader: &dyn traffic_protocol::evidence::ValueReader,
    ) -> Result<Option<traffic_protocol::evidence::ValueEvidence>> {
        value_query::query(event, payload, query, reader).map(Some)
    }

    fn schema(&self) -> &'static str {
        "mysql/semantic-evidence/v2"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &[
            "mysql_exchange",
            "mysql_connection",
            "mysql_tls_rejected",
            "mysql_query",
            "mysql_response",
        ]
    }
    fn recording_safety_issue(&self, value: &Value) -> Option<String> {
        let event_type = value["event_type"].as_str().unwrap_or_default();
        if event_type == "mysql_exchange" {
            let terminated = value.get("outcome").is_some_and(Value::is_object);
            if value["response"]["status"] == "incomplete"
                || terminated
                    && value["parse_warnings"]
                        .as_array()
                        .is_some_and(|warnings| !warnings.is_empty())
            {
                return Some(
                    "mysql_exchange contains incomplete or unsupported transport capture evidence"
                        .into(),
                );
            }
        }
        None
    }
    fn include_in_recording_summary(&self, event: &Value) -> bool {
        event["event_type"] != "mysql_exchange"
            || event["capture"]["semantic_required"] != false
                && !crate::capture::is_debug_only_mysql_exchange_value(event)
    }
    fn recording_summary(
        &self,
    ) -> Option<Box<dyn traffic_protocol::observation::RecordingSummary>> {
        Some(Box::new(
            crate::recording_summary::MysqlDependencySummary::default(),
        ))
    }
    fn source_payload(
        &self,
        protocol: &str,
        event: &Value,
        side: traffic_protocol::evidence::MessageSide,
        _secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
    ) -> Result<Option<Vec<u8>>> {
        if protocol != "mysql" || event["event_type"] != "mysql_exchange" {
            return Ok(None);
        }
        crate::witness::source_payload(event, side).map(Some)
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["event_type"] == "mysql_exchange"
            && event["replay_safe"] != false
            && !event["parse_warnings"].as_array().is_some_and(|warnings| {
                warnings.iter().any(|warning| {
                    warning
                        .as_str()
                        .is_some_and(|warning| warning.contains("unsupported"))
                })
            })
    }
    fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
        if event["event_type"] != "mysql_exchange" {
            return Ok(None);
        }
        let command = event["command"]
            .as_str()
            .context("Source MySQL command missing")?;
        if crate::is_no_response_command(command)
            || command == "COM_PING"
            || command == "COM_STMT_PREPARE" && event["response"]["status"] == "stmt_prepare"
        {
            return Ok(None);
        }
        let connection = event["connection_id"]
            .as_str()
            .context("Source MySQL connection identity missing")?
            .parse()?;
        let sequence = event["query_sequence"]
            .as_u64()
            .context("Source MySQL exchange sequence missing")?;
        Ok(Some(ProtocolRef::connection("mysql", connection, sequence)))
    }
    fn source_timing(&self, event: &Value) -> SourceTiming {
        if event["event_type"] != "mysql_exchange" {
            return SourceTiming::Control;
        }
        let clock = |field: &str| event[field].as_str().and_then(|value| value.parse().ok());
        SourceTiming::Request {
            started_at: clock("request_started_at"),
            completed_at: clock("timestamp"),
        }
    }
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        if event["event_type"] != "mysql_exchange" {
            return None;
        }
        let command = event["command"].as_str().unwrap_or("unknown");
        if crate::maintenance::is_mysql_maintenance_exchange(command, event["sql"].as_str()) {
            return None;
        }
        let endpoint = optional_endpoint(
            event["target_host"].as_str(),
            event["target_port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok()),
            event["target_addr"]
                .as_str()
                .or_else(|| event["upstream_addr"].as_str()),
        );
        Some(TrafficInteraction {
            protocol: "mysql".into(),
            endpoint,
            operation: command.to_ascii_uppercase(),
        })
    }
}

mod discovery;
mod value_query;
