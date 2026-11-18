//! Read-only index compatibility for retired providers; no execution capability.
use anyhow::Result;
use serde_json::{Value, json};
use traffic_protocol::evidence::{
    EvidenceAdapter,
    index::{IndexEndpoint, IndexProjection},
};

pub struct Historical;
impl EvidenceAdapter for Historical {
    fn capture_complete(&self, event: &Value) -> bool {
        event["replay_safe"] != false
            && event["response"]["status"] != "incomplete"
            && event["request_body"]["truncated"] != true
            && event["response_body"]["truncated"] != true
            && event["response"]["truncated"] != true
            && event["response"]["rows_truncated"] != true
    }

    fn proof_selector(&self, event: &Value) -> Value {
        traffic_protocol::evidence::index::select_without(
            event,
            &[
                "request_body",
                "response_body",
                "request",
                "response",
                "response_frames",
                "value",
                "headers",
                "raw",
                "request_headers",
                "protected_request_headers",
            ],
            &[],
        )
    }
    fn schema(&self) -> &'static str {
        "historical-index/v1"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &[
            "memcached_connection",
            "memcached_exchange",
            "kafka_connection",
            "kafka_produce",
            "kafka_fetch",
            "kafka_delivery",
            "motan_connection",
            "motan_exchange",
        ]
    }
    fn supports_interaction_inventory(&self) -> bool {
        false
    }
    fn supports_replay(&self, _: &Value) -> bool {
        false
    }
    fn index_projection(&self, event: &Value) -> Result<IndexProjection> {
        traffic_protocol::evidence::index::compact_unknown(event)
    }
    fn lookup_projection(&self, event: &Value) -> Result<IndexProjection> {
        let mut projection = self.index_projection(event)?;
        let tag = event["event_type"].as_str().unwrap_or_default();
        if let Some((host, port)) = event["target_host"]
            .as_str()
            .zip(event["target_port"].as_u64())
        {
            projection.endpoints.push(IndexEndpoint {
                host: host.trim_end_matches('.').to_ascii_lowercase(),
                port: u16::try_from(port)?,
                protocol: tag.split('_').next().unwrap_or_default().into(),
            });
        }
        if tag.ends_with("_connection") {
            projection.observations.push(projection.record.clone());
        }
        if tag == "motan_exchange" && event["advertised_ip"].is_string() {
            projection.observations.push(json!({"event_type":"indexed_advertised_target", "target": {
                "alias":event["target_host"],"port":event["target_port"],"protocol":"motan","advertised_ip":event["advertised_ip"]
            }}));
        }
        Ok(projection)
    }
}
