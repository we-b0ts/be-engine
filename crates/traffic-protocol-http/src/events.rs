//! Native capture payloads, independent of recording lifecycle and storage.
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use traffic_model::DiscoveredTcpTarget;
use traffic_model::{DependencyExchangeOutcome, capture::BodyCapture};
use uuid::Uuid;
pub type HeaderMapSnapshot = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Serialize)]
pub struct HttpExchangeEvent {
    pub outcome: DependencyExchangeOutcome,
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub request_started_at: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub scheme: String,
    pub method: String,
    pub uri: String,
    pub authority: Option<String>,
    pub request_headers: HeaderMapSnapshot,
    pub request_body: BodyCapture,
    pub response_status: Option<u16>,
    pub response_headers: Option<HeaderMapSnapshot>,
    pub response_body: Option<BodyCapture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_stream: Option<crate::stream::ResponseStream>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_tcp_targets: Vec<DiscoveredTcpTarget>,
    pub duration_ms: u128,
    pub error: Option<String>,
}
