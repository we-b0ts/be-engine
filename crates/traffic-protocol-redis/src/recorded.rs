//! Native stored RESP messages and notification references.
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use traffic_model::DependencyExchangeOutcome;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct RecordedConnection {
    pub target_host: String,
    pub target_port: u16,
    pub replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecordedExchange {
    // Subscription aliases retain event identity without changing existing
    // Redis rule/evidence fingerprints, which serialize this projection.
    #[serde(default, skip_serializing)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub target_host: String,
    pub target_port: u16,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub command: String,
    pub args: Vec<RecordedCapture>,
    pub response_kind: String,
    pub response: RecordedCapture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_callback_capture: Option<String>,
    #[serde(default)]
    pub outcome: DependencyExchangeOutcome,
    #[serde(default)]
    pub duration_ms: u64,
    pub replay_safe: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parse_warnings: Vec<String>,
    #[serde(default)]
    pub cache_snapshot_rule: Option<String>,
    #[serde(default)]
    pub cache_snapshot_hit: bool,
    #[serde(default)]
    pub session_setup: bool,
    #[serde(default)]
    pub capture: Option<traffic_model::recording::CaptureMetadata>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecordedCapture {
    pub encoding: String,
    pub data: String,
    #[serde(default)]
    pub truncated: bool,
}

impl RecordedCapture {
    pub fn decode(&self) -> Result<Vec<u8>> {
        if self.truncated {
            return Err(anyhow!("recorded Redis capture is truncated"));
        }
        match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("invalid Redis capture base64"),
            "utf8" => Ok(self.data.as_bytes().to_vec()),
            other => Err(anyhow!("unsupported Redis capture encoding {other}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RecordedPush {
    #[serde(default)]
    capture: Option<PushCaptureIdentity>,
    #[serde(default)]
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub target_host: String,
    pub target_port: u16,
    pub database: i64,
    pub username: Option<String>,
    pub connection_id: Uuid,
    pub subscription_sequence: u64,
    pub rpc_request: Option<RequestRef>,
    pub response: RecordedCapture,
    pub duration_ms: u64,
    pub replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct PushCaptureIdentity {
    exchange_id: Uuid,
}

impl RecordedPush {
    pub fn source_exchange_id(&self) -> Option<Uuid> {
        self.capture.as_ref().map(|capture| capture.exchange_id)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestRef {
    pub connection_id: Uuid,
    pub sequence: u64,
    #[serde(default)]
    pub case_id: Option<String>,
}
