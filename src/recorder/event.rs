//! Protocol-independent recording case identity.
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaseContext {
    pub id: Uuid,
    pub rule_name: String,
    pub uri_group: Option<String>,
}

use chrono::{DateTime, Utc};
#[derive(Debug, Clone, Serialize)]
pub struct DependencyConnectFailureEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
    pub duration_ms: u128,
    pub failure_kind: String,
    pub client_outcome: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyErrorEvent {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
    pub client_addr: Option<String>,
    pub target: Option<String>,
    pub error: String,
}

impl traffic_protocol::capture::CaptureEvidence for ProxyErrorEvent {
    fn event_type(&self) -> &'static str {
        "proxy_error"
    }
    fn capture_facts(&self) -> traffic_protocol::capture::CaptureFacts {
        let mut facts = traffic_protocol::capture::CaptureFacts::observation(
            traffic_model::recording::ProtocolRef::observation(self.id, "proxy_error"),
        );
        facts.terminal = "capture_failed".into();
        facts.complete = false;
        facts.traffic_error = true;
        facts
    }
}
impl traffic_protocol::capture::CaptureEvidence for DependencyConnectFailureEvent {
    fn event_type(&self) -> &'static str {
        "dependency_connect_failure"
    }
    fn capture_facts(&self) -> traffic_protocol::capture::CaptureFacts {
        let mut facts = traffic_protocol::capture::CaptureFacts::dependency(
            traffic_model::recording::ProtocolRef::observation(
                self.id,
                "dependency_connect_failure",
            ),
            "connect_failed",
            true,
        );
        facts.traffic_error = true;
        facts
    }
}
