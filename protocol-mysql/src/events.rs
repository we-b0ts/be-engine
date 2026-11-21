//! Native capture payloads, independent of recording lifecycle and storage.
use crate::semantic::{MysqlExchangeResponse, MysqlValue};
use chrono::{DateTime, Utc};
use serde::Serialize;
use traffic_model::{DependencyExchangeOutcome, capture::BodyCapture};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct MysqlConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<String>,
    pub upstream_addr: String,
    pub username: Option<String>,
    pub database: Option<String>,
    pub capability_flags: Option<u32>,
    pub duration_ms: Option<u128>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlQueryEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub command: String,
    pub query: Option<String>,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlPacketEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub query_sequence: Option<u64>,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub direction: String,
    pub sequence_id: u8,
    pub payload_len: usize,
    pub payload: Option<BodyCapture>,
    pub packet_kind: Option<String>,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlResponseEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub query_sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub status: String,
    pub packet_count: usize,
    pub payload_bytes: usize,
    pub duration_ms: u128,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
    pub payload: BodyCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<Vec<MysqlResponsePacket>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlResponsePacket {
    pub sequence_id: u8,
    pub packet_kind: String,
    pub payload_len: usize,
    pub payload: BodyCapture,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlExchangeEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub query_sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub request_started_at: DateTime<Utc>,
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    pub command: String,
    pub sql: Option<String>,
    pub statement_id: Option<u32>,
    pub params: Option<Vec<MysqlValue>>,
    /// Last confirmed status before this command, on the same wire sequence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_status_before: Option<u16>,
    pub response: MysqlExchangeResponse,
    pub outcome: DependencyExchangeOutcome,
    pub duration_ms: u128,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MysqlTlsRejectedEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<String>,
    pub upstream_addr: String,
    pub capability_flags: u32,
    pub reason: String,
}
