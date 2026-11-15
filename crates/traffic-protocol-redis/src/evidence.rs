//! Native semantic evidence support, independent of inventory and ownership.
use anyhow::{Context, Result};
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::evidence::{EvidenceAdapter, SourceTiming};
use traffic_protocol::observation::{NativeSummary, TrafficInteraction, format_endpoint};

pub struct NativeEvidence;
impl EvidenceAdapter for NativeEvidence {
    fn schema(&self) -> &'static str {
        "redis/semantic-evidence/v2"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["redis_exchange", "redis_pub_sub_push", "redis_connection"]
    }
    fn recording_safety_issue(&self, value: &Value) -> Option<String> {
        let event_type = value["event_type"].as_str().unwrap_or_default();
        if matches!(
            event_type,
            "redis_connection" | "redis_exchange" | "redis_pub_sub_push"
        ) && value
            .get("replay_safe")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            let command = value
                .get("command")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            return Some(format!(
                "{event_type} command {command} contains incomplete or unsupported replay evidence"
            ));
        }
        if event_type == "proxy_error"
            && matches!(
                value.get("protocol").and_then(serde_json::Value::as_str),
                Some("redis")
            )
        {
            return Some(format!(
                "dependency proxy error: {}",
                value
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown dependency proxy error")
            ));
        }
        None
    }
    fn include_in_recording_summary(&self, event: &Value) -> bool {
        event["event_type"] == "redis_connection" || event["capture"]["semantic_required"] != false
    }
    fn recording_summary(
        &self,
    ) -> Option<Box<dyn traffic_protocol::observation::RecordingSummary>> {
        Some(Box::new(
            crate::recording_summary::RedisSummaryBuilder::default(),
        ))
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["replay_safe"] != false
            && matches!(
                event["event_type"].as_str(),
                Some("redis_exchange" | "redis_pub_sub_push")
            )
    }
    fn supports_input_timing(&self, event_type: &str) -> bool {
        matches!(event_type, "redis_exchange" | "redis_pub_sub_push")
    }
    fn source_timing(&self, event: &Value) -> SourceTiming {
        match event["event_type"].as_str() {
            Some("redis_connection") => SourceTiming::Control,
            Some("redis_pub_sub_push") => SourceTiming::Notification,
            _ => {
                let clock =
                    |field: &str| event[field].as_str().and_then(|value| value.parse().ok());
                SourceTiming::Request {
                    started_at: clock("request_started_at"),
                    completed_at: clock("timestamp"),
                }
            }
        }
    }

    fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
        let (protocol, identity) = match event["event_type"].as_str() {
            Some("redis_exchange") => ("redis", event),
            Some("redis_pub_sub_push") if event["rpc_request"].is_object() => {
                ("redis_rpc_push", &event["rpc_request"])
            }
            _ => return Ok(None),
        };
        let connection = identity["connection_id"]
            .as_str()
            .context("Source Redis connection identity missing")?
            .parse()?;
        let sequence = identity["sequence"]
            .as_u64()
            .context("Source Redis exchange sequence missing")?;
        Ok(Some(ProtocolRef::connection(
            protocol, connection, sequence,
        )))
    }

    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let command = event["command"].as_str().unwrap_or("unknown");
        if event["event_type"] != "redis_exchange"
            || event["session_setup"] == true
            || command.eq_ignore_ascii_case("PING")
        {
            return None;
        }
        let endpoint = event["target_host"]
            .as_str()
            .zip(
                event["target_port"]
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok()),
            )
            .map(|(host, port)| format_endpoint(host, port));
        Some(TrafficInteraction {
            protocol: "redis".into(),
            endpoint,
            operation: command.to_ascii_uppercase(),
        })
    }

    fn process_summary_types(&self) -> &'static [&'static str] {
        &["redis_snapshot"]
    }
    fn process_summary_key(&self, event: &Value) -> Option<&'static str> {
        (event["event_type"] == "redis_exchange" && event["cache_snapshot_rule"].as_str().is_some())
            .then_some("redis_snapshot")
    }
    fn process_summary(&self, name: &str) -> Option<Box<dyn NativeSummary>> {
        (name == "redis_snapshot").then(|| {
            Box::new(crate::process_summary::SnapshotAccumulator::default())
                as Box<dyn NativeSummary>
        })
    }
}
