//! Native semantic evidence support, independent of inventory and ownership.
use serde_json::Value;
use traffic_protocol::evidence::EvidenceAdapter;
use traffic_protocol::observation::{NativeSummary, TrafficInteraction, format_endpoint};

pub struct NativeEvidence;
impl EvidenceAdapter for NativeEvidence {
    fn schema(&self) -> &'static str {
        "redis/semantic-evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["redis_exchange", "redis_pub_sub_push"]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["replay_safe"] != false
            && matches!(
                event["event_type"].as_str(),
                Some("redis_exchange" | "redis_pub_sub_push")
            )
    }

    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let command = event["command"].as_str()?;
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
