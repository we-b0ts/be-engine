//! Native capture payloads, independent of recording lifecycle and storage.
use chrono::{DateTime, Utc};
use serde::Serialize;
use traffic_model::{DependencyExchangeOutcome, capture::BodyCapture};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct RedisConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub phase: String,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub duration_ms: Option<u128>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub replay_safe: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisExchangeEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    /// Original request observation; duration_ms is a truncated scheduling hint.
    pub request_started_at: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub command: String,
    pub args: Vec<BodyCapture>,
    pub response_kind: String,
    pub response: BodyCapture,
    /// A completed capture window may contain no RPC callback. Legacy evidence
    /// without this marker cannot establish that bounded observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_callback_capture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_snapshot_rule: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cache_snapshot_hit: bool,
    pub session_setup: bool,
    pub outcome: DependencyExchangeOutcome,
    pub duration_ms: u128,
    pub replay_safe: bool,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisPubSubPushEvent {
    pub timestamp: DateTime<Utc>,
    pub target_host: String,
    pub target_port: u16,
    pub database: i64,
    pub username: Option<String>,
    pub connection_id: Uuid,
    pub subscription_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_request: Option<RedisRpcRequestRef>,
    pub response: BodyCapture,
    pub duration_ms: u64,
    pub replay_safe: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisRpcRequestRef {
    pub connection_id: Uuid,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Uuid>,
}
