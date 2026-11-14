//! Native semantic evidence support, independent of inventory and ownership.
use serde_json::Value;
use traffic_protocol::evidence::EvidenceAdapter;

pub struct NativeEvidence;
impl EvidenceAdapter for NativeEvidence {
    fn schema(&self) -> &'static str {
        "redis/semantic-evidence/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["redis_exchange", "redis_pub_sub_push"]
    }
    fn supports_replay(&self, event: &Value) -> bool {
        matches!(
            event["event_type"].as_str(),
            Some("redis_exchange" | "redis_pub_sub_push")
        )
    }
}
