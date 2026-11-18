//! Native semantic evidence support, independent of inventory and ownership.
use anyhow::{Context, Result};
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::evidence::{EvidenceAdapter, SourceTiming};
use traffic_protocol::observation::{TrafficInteraction, format_endpoint};

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
        "http/semantic-evidence/v2"
    }
    fn event_types(&self) -> &'static [&'static str] {
        &["http_exchange"]
    }
    fn include_in_recording_summary(&self, _event: &Value) -> bool {
        true
    }
    fn recording_summary(
        &self,
    ) -> Option<Box<dyn traffic_protocol::observation::RecordingSummary>> {
        Some(Box::new(
            crate::recording_summary::HttpDependencySummary::default(),
        ))
    }
    fn source_payload(
        &self,
        protocol: &str,
        event: &Value,
        side: traffic_protocol::evidence::MessageSide,
        secrets: &dyn traffic_protocol::evidence::EvidenceSecrets,
    ) -> Result<Option<Vec<u8>>> {
        if protocol != "http" || event["event_type"] != "http_exchange" {
            return Ok(None);
        }
        crate::witness::source_payload(event, side, secrets).map(Some)
    }
    fn supports_replay(&self, event: &Value) -> bool {
        event["event_type"] == "http_exchange" && event["replay_safe"] != false
    }
    fn source_timing(&self, event: &Value) -> SourceTiming {
        let clock = |field: &str| event[field].as_str().and_then(|value| value.parse().ok());
        SourceTiming::Request {
            started_at: clock("request_started_at"),
            completed_at: clock("timestamp"),
        }
    }
    fn connection_endpoint(
        &self,
        event: &Value,
    ) -> Result<Option<traffic_protocol::connection::Endpoint>> {
        let authority = event["authority"]
            .as_str()
            .context("connection ordering requires the HTTP physical authority")?
            .parse::<hyper::http::uri::Authority>()
            .context("invalid HTTP authority before a failed connect")?;
        let default_port = match event["scheme"].as_str() {
            Some("http" | "fake_ip_http" | "http_gateway") => 80,
            Some("https" | "fake_ip_https") => 443,
            _ => anyhow::bail!("unsupported HTTP scheme before a failed connect"),
        };
        Ok(Some(traffic_protocol::connection::Endpoint {
            host: traffic_protocol::observation::normalize_host(authority.host()),
            port: authority.port_u16().unwrap_or(default_port),
        }))
    }
    fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
        let exchange_id = event["id"]
            .as_str()
            .context("Source HTTP exchange identity missing")?
            .parse()?;
        Ok(Some(ProtocolRef::exchange("http", exchange_id)))
    }
    fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let method = event["method"].as_str().unwrap_or("unknown");
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

mod value_query;
