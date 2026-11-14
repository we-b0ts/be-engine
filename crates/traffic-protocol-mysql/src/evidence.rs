//! Native semantic evidence support, independent of inventory and ownership.
use serde_json::Value;
use traffic_protocol::evidence::EvidenceAdapter;

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
            && !event["parse_warnings"].as_array().is_some_and(|warnings| {
                warnings.iter().any(|warning| {
                    warning
                        .as_str()
                        .is_some_and(|warning| warning.contains("unsupported"))
                })
            })
    }
}
