//! Native MySQL diagnostic payloads retain caller-supplied Source scope identities.
use super::SqlSummary;
use serde::Serialize;
use serde_json::Value;
use traffic_protocol::connection::Endpoint;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionReport {
    pub peer_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryReport<Source> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<crate::model::MysqlValue>>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_source: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchedQueryReport<Source> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_query_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub source: Source,
    pub index: usize,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<crate::model::MysqlValue>>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordedExchangeSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_sequence: Option<u64>,
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<Endpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql_summary: Option<SqlSummary>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<usize>,
}
