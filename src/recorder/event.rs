use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::dependency::{DependencyExchangeOutcome, DiscoveredTcpTarget};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BodyCapture {
    pub encoding: &'static str,
    pub original_len: usize,
    pub stored_len: usize,
    pub truncated: bool,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaseBodyCapture {
    pub encoding: &'static str,
    pub original_len: usize,
    pub stored_len: usize,
    pub limit_bytes: usize,
    pub truncated: bool,
    pub decoded: bool,
    pub content_encoding: Option<String>,
    pub data: String,
    pub decode_error: Option<String>,
}

pub type HeaderMapSnapshot = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CaseContext {
    pub id: Uuid,
    pub rule_name: String,
    pub uri_group: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum RecorderEvent {
    HttpExchange(HttpExchangeEvent),
    TcpGatewayConnection(TcpGatewayConnectionEvent),
    UdpDatagram(UdpDatagramEvent),
    RedisConnection(RedisConnectionEvent),
    RedisExchange(RedisExchangeEvent),
    RedisPubSubPush(RedisPubSubPushEvent),
    MemcachedConnection(MemcachedConnectionEvent),
    MemcachedExchange(MemcachedExchangeEvent),
    KafkaConnection(KafkaConnectionEvent),
    KafkaProduce(KafkaProduceEvent),
    KafkaFetch(KafkaFetchEvent),
    KafkaDelivery(KafkaDeliveryEvent),
    MotanConnection(MotanConnectionEvent),
    MotanExchange(MotanExchangeEvent),
    MysqlConnection(MysqlConnectionEvent),
    MysqlQuery(MysqlQueryEvent),
    MysqlResponse(MysqlResponseEvent),
    MysqlExchange(MysqlExchangeEvent),
    MysqlPacket(MysqlPacketEvent),
    MysqlTlsRejected(MysqlTlsRejectedEvent),
    AccessPolicyAllow(AccessPolicyAllowEvent),
    ReadonlyRejection(ReadonlyRejectionEvent),
    ProxyError(ProxyErrorEvent),
}

impl RecorderEvent {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::HttpExchange(_) => "http_exchange",
            Self::TcpGatewayConnection(_) => "tcp_gateway_connection",
            Self::UdpDatagram(_) => "udp_datagram",
            Self::RedisConnection(_) => "redis_connection",
            Self::RedisExchange(_) => "redis_exchange",
            Self::RedisPubSubPush(_) => "redis_pub_sub_push",
            Self::MemcachedConnection(_) => "memcached_connection",
            Self::MemcachedExchange(_) => "memcached_exchange",
            Self::KafkaConnection(_) => "kafka_connection",
            Self::KafkaProduce(_) => "kafka_produce",
            Self::KafkaFetch(_) => "kafka_fetch",
            Self::KafkaDelivery(_) => "kafka_delivery",
            Self::MotanConnection(_) => "motan_connection",
            Self::MotanExchange(_) => "motan_exchange",
            Self::MysqlConnection(_) => "mysql_connection",
            Self::MysqlQuery(_) => "mysql_query",
            Self::MysqlResponse(_) => "mysql_response",
            Self::MysqlExchange(_) => "mysql_exchange",
            Self::MysqlPacket(_) => "mysql_packet",
            Self::MysqlTlsRejected(_) => "mysql_tls_rejected",
            Self::AccessPolicyAllow(_) => "access_policy_allow",
            Self::ReadonlyRejection(_) => "readonly_rejection",
            Self::ProxyError(_) => "proxy_error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpExchangeEvent {
    pub outcome: crate::DependencyExchangeOutcome,
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
    pub response_stream: Option<super::HttpResponseStream>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_tcp_targets: Vec<DiscoveredTcpTarget>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

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
pub struct TcpGatewayConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub domain: Option<String>,
    pub fake_addr: String,
    pub upstream_addr: Option<String>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub duration_ms: u128,
    pub error: Option<String>,
}

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

/// An asynchronous reply linked to the original PUBLISH, across TCP connections.
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

#[derive(Debug, Clone, Serialize)]
pub struct MemcachedConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub phase: String,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub wire_protocol: String,
    pub duration_ms: Option<u128>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub replay_safe: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemcachedExchangeEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub wire_protocol: String,
    pub command: String,
    pub opcode: Option<u8>,
    pub opaque: Option<u32>,
    pub key: Option<BodyCapture>,
    pub args: Vec<BodyCapture>,
    pub value: Option<BodyCapture>,
    pub extras: Option<BodyCapture>,
    pub cas: Option<u64>,
    pub noreply: bool,
    pub quiet: bool,
    pub response_status: String,
    pub response_frames: Vec<BodyCapture>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_frame_offsets_ms: Vec<u128>,
    pub no_response: bool,
    pub outcome: DependencyExchangeOutcome,
    pub duration_ms: u128,
    pub replay_safe: bool,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub phase: String,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub duration_ms: Option<u128>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub replay_safe: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KafkaHeaderCapture {
    pub name: String,
    pub value: Option<BodyCapture>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaProduceEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub request_sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub api_version: i16,
    pub topic: String,
    pub key: Option<BodyCapture>,
    pub headers: Vec<KafkaHeaderCapture>,
    pub value: Option<BodyCapture>,
    pub result: String,
    pub outcome: DependencyExchangeOutcome,
    pub duration_ms: u128,
    pub replay_safe: bool,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaFetchEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub api_version: i16,
    pub topics: Vec<String>,
    pub outcome: DependencyExchangeOutcome,
    pub duration_ms: u128,
    pub replay_safe: bool,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaDeliveryEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub fetch_sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub upstream_addr: String,
    pub api_version: i16,
    pub topic: String,
    pub key: Option<BodyCapture>,
    pub headers: Vec<KafkaHeaderCapture>,
    pub value: Option<BodyCapture>,
    pub message_timestamp_ms: i64,
    pub replay_safe: bool,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotanConnectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub phase: String,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub advertised_ip: std::net::Ipv4Addr,
    pub upstream_addr: String,
    pub duration_ms: Option<u128>,
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
    pub replay_safe: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotanExchangeEvent {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub client_addr: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    pub target_addr: String,
    pub advertised_ip: std::net::Ipv4Addr,
    pub upstream_addr: String,
    pub codec_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub interface_name: Option<String>,
    pub method_name: Option<String>,
    pub parameter_desc: Option<String>,
    pub method_sign: Option<String>,
    pub command: String,
    pub request: BodyCapture,
    pub response_status: String,
    pub response: BodyCapture,
    pub heartbeat: bool,
    pub outcome: DependencyExchangeOutcome,
    pub duration_ms: u128,
    pub replay_safe: bool,
    pub parse_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UdpDatagramEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_addr: Option<String>,
    pub protocol: String,
    pub forwarded: bool,
    pub payload: BodyCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_text: Option<String>,
    pub duration_ms: u128,
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

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlWirePrefixPacket {
    pub offset_ms: u128,
    pub packet: BodyCapture,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlExchangeResponse {
    /// Complete wire packets already delivered before transport termination.
    /// These are dependency evidence, never a synthesized successful resultset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wire_prefix: Vec<MysqlWirePrefixPacket>,
    /// Protocol-41 OK or final resultset EOF status, when captured completely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_status: Option<u16>,
    pub status: String,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
    pub affected_rows: Option<u64>,
    pub last_insert_id: Option<u64>,
    pub columns: Vec<MysqlColumn>,
    pub rows: Vec<Vec<MysqlValue>>,
    pub row_count: usize,
    pub rows_truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MysqlColumn {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    pub family: String,
    pub sql_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<u8>,
    #[serde(skip_serializing)]
    pub column_type_code: u8,
    #[serde(skip_serializing)]
    pub flags: Option<u16>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MysqlValue {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<BodyCapture>,
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

#[derive(Debug, Clone, Serialize)]
pub struct ReadonlyRejectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub access_policy: String,
    pub protocol: String,
    pub operation_class: String,
    pub operation: String,
    pub client_addr: Option<String>,
    pub target: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessPolicyAllowEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub access_policy: String,
    pub rule: String,
    pub protocol: String,
    pub operation_class: String,
    pub operations: Vec<String>,
    pub resources: Vec<String>,
    pub client_addr: Option<String>,
    pub target: Option<String>,
    pub reason: String,
}
