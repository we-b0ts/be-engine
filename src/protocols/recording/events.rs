//! Native recording schemas assembled by the application.
pub use crate::recorder::{DependencyConnectFailureEvent, ProxyErrorEvent};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::dependency::DependencyExchangeOutcome;

pub use traffic_model::capture::BodyCapture;
pub use traffic_protocol_http::body_capture::{capture_case_body, redact_headers};

pub use traffic_protocol_http::events::{CaseBodyCapture, HeaderMapSnapshot};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum RecorderEvent {
    DependencyConnectFailure(DependencyConnectFailureEvent),
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
            Self::DependencyConnectFailure(_) => "dependency_connect_failure",
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

/// An actual failed upstream connect and the transport failure sent to Source.
/// Protocol parsing and recorder failures must never use this observation.
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

/// An asynchronous reply linked to the original PUBLISH, across TCP connections.

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
    pub request_started_at: DateTime<Utc>,
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

pub use traffic_protocol_mysql::semantic::{MysqlColumn, MysqlExchangeResponse, MysqlValue};

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

pub use traffic_protocol_http::events::HttpExchangeEvent;

pub use traffic_protocol_redis::events::{
    RedisConnectionEvent, RedisExchangeEvent, RedisPubSubPushEvent, RedisRpcRequestRef,
};

pub use traffic_protocol_mysql::events::{
    MysqlConnectionEvent, MysqlExchangeEvent, MysqlPacketEvent, MysqlQueryEvent,
    MysqlResponseEvent, MysqlResponsePacket, MysqlTlsRejectedEvent,
};
