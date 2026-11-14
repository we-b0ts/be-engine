//! Native semantic evidence support, independent of inventory and ownership.
use serde_json::Value;
use traffic_protocol::evidence::EvidenceAdapter;
use traffic_protocol::observation::{TrafficInteraction, format_endpoint};

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
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let method = event["method"].as_str()?;
        let endpoint = event["authority"].as_str().and_then(|authority| {
            let authority = authority.parse::<hyper::http::uri::Authority>().ok()?;
            let port = authority.port_u16().or(match event["scheme"].as_str()? {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            })?;
            Some(format_endpoint(authority.host(), port))
        });
        Some(TrafficInteraction {
            protocol: "http".into(),
            endpoint,
            operation: method.to_ascii_uppercase(),
        })
    }
}
