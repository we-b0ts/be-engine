//! Native semantic evidence support, independent of inventory and ownership.
use serde_json::Value;
use traffic_protocol::evidence::EvidenceAdapter;
use traffic_protocol::observation::{TrafficInteraction, optional_endpoint};

pub struct NativeEvidence;
impl EvidenceAdapter for NativeEvidence {
    fn schema(&self) -> &'static str {
        "mysql/semantic-evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["mysql_exchange"]
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
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let command = event["command"].as_str()?;
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
