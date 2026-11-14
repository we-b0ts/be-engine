//! Native semantic evidence support, independent of inventory and ownership.
use serde_json::Value;
use traffic_protocol::evidence::EvidenceAdapter;

pub struct NativeEvidence;
impl EvidenceAdapter for NativeEvidence {
    fn schema(&self) -> &'static str {
        "http/semantic-evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["http_exchange"]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["event_type"] == "http_exchange"
    }
}
