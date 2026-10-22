use std::collections::BTreeSet;

use super::*;
use crate::DependencyExchangeOutcome;

#[derive(Debug, Default)]
pub(in crate::replay) struct ReplayEvents {
    pub(in crate::replay) global_report:
        crate::replay::report::global_evidence::regular_usage::Usage,
    pub(in crate::replay) dirty_case_ids: BTreeSet<String>,
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) connection_events: Vec<ConnectionReport>,
    pub(in crate::replay) builtin_query_count: usize,
    pub(in crate::replay) builtin_queries: Vec<QueryReport>,
    pub(in crate::replay) builtin_query_details: SuccessDetailBudget,
    pub(in crate::replay) matched_query_count: usize,
    pub(in crate::replay) matched_queries: Vec<MatchedQueryReport>,
    pub(in crate::replay) matched_query_details: SuccessDetailBudget,
    pub(in crate::replay) unmatched_queries: Vec<QueryReport>,
    pub(in crate::replay) unsupported_commands: Vec<QueryReport>,
    pub(in crate::replay) metadata_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct ReplayExchange {
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) identity: MysqlDependencyIdentity,
    pub(in crate::replay) record: RecordedMysqlExchange,
    pub(in crate::replay) optional_session: Option<OptionalSessionExchange>,
    pub(in crate::replay) status: ReplayExchangeStatus,
    pub(in crate::replay) timing: ReplayExchangeTiming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::replay) enum OptionalSessionExchange {
    Rollback,
    Commit,
    Autocommit,
    TransactionAutocommit,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct MatchedExchange {
    pub(in crate::replay) transaction_owner: Option<Option<String>>,
    pub(in crate::replay) value_delivery: Option<contracts::PreparedDelivery>,
    pub(in crate::replay) identity_delivery: Option<policy::dynamic_values::MysqlIdentityDelivery>,
    pub(in crate::replay) response_time_shift_rules: Vec<String>,
    #[allow(dead_code)]
    pub(in crate::replay) source: ReplaySource,
    #[allow(dead_code)]
    pub(in crate::replay) index: usize,
    pub(in crate::replay) record: RecordedMysqlExchange,
    pub(in crate::replay) timing: ReplayExchangeTiming,
    pub(in crate::replay) report: MatchedQueryReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::replay) struct MysqlDependencyIdentity {
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) database: Option<String>,
    pub(in crate::replay) username: Option<String>,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct ReplaySessionIdentity {
    pub(in crate::replay) target: Option<TargetKey>,
    pub(in crate::replay) database: Option<String>,
    pub(in crate::replay) username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedMysqlConnection {
    pub(in crate::replay) id: Uuid,
    pub(in crate::replay) target_host: Option<String>,
    pub(in crate::replay) target_port: Option<u16>,
    pub(in crate::replay) target_addr: Option<String>,
    pub(in crate::replay) database: Option<String>,
    pub(in crate::replay) username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedMysqlExchange {
    #[serde(default)]
    pub(in crate::replay) timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub(in crate::replay) server_status_before: Option<u16>,
    pub(in crate::replay) query_sequence: Option<u64>,
    pub(in crate::replay) connection_id: Option<Uuid>,
    pub(in crate::replay) target_host: Option<String>,
    pub(in crate::replay) target_port: Option<u16>,
    pub(in crate::replay) target_addr: Option<String>,
    pub(in crate::replay) database: Option<String>,
    pub(in crate::replay) username: Option<String>,
    pub(in crate::replay) command: String,
    pub(in crate::replay) sql: Option<String>,
    pub(in crate::replay) params: Option<Vec<RecordedMysqlValue>>,
    pub(in crate::replay) response: RecordedMysqlResponse,
    #[serde(default)]
    pub(in crate::replay) parse_warnings: Vec<String>,
    #[serde(default)]
    pub(in crate::replay) outcome: DependencyExchangeOutcome,
    #[serde(default)]
    pub(in crate::replay) duration_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(in crate::replay) struct RecordedMysqlResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) wire_prefix: Vec<RecordedMysqlWirePrefixPacket>,
    #[serde(skip)]
    pub(in crate::replay) evidence: Option<crate::dependency_index::RecordRef>,
    #[serde(skip)]
    pub(in crate::replay) row_shape: Option<(usize, bool)>,
    pub(in crate::replay) server_status: Option<u16>,
    pub(in crate::replay) status: String,
    pub(in crate::replay) error_code: Option<u16>,
    pub(in crate::replay) error_message: Option<String>,
    pub(in crate::replay) affected_rows: Option<u64>,
    pub(in crate::replay) last_insert_id: Option<u64>,
    #[serde(default)]
    pub(in crate::replay) columns: Vec<RecordedMysqlColumn>,
    #[serde(default)]
    pub(in crate::replay) rows: Vec<Vec<RecordedMysqlValue>>,
    #[serde(default)]
    pub(in crate::replay) rows_truncated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(in crate::replay) struct RecordedMysqlWirePrefixPacket {
    pub(in crate::replay) offset_ms: u64,
    pub(in crate::replay) packet: RecordedMysqlWireCapture,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(in crate::replay) struct RecordedMysqlWireCapture {
    pub(in crate::replay) encoding: String,
    pub(in crate::replay) data: String,
    #[serde(default)]
    pub(in crate::replay) truncated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(in crate::replay) struct RecordedMysqlColumn {
    pub(in crate::replay) name: String,
    pub(in crate::replay) table: Option<String>,
    /// Delivered table label; the recording's table remains the physical origin.
    #[serde(skip)]
    pub(in crate::replay) table_alias: Option<String>,
    pub(in crate::replay) column: Option<String>,
    pub(in crate::replay) family: String,
    pub(in crate::replay) sql_type: String,
    pub(in crate::replay) unsigned: Option<bool>,
    pub(in crate::replay) bits: Option<u16>,
    pub(in crate::replay) nullable: Option<bool>,
    pub(in crate::replay) scale: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(in crate::replay) struct RecordedMysqlValue {
    pub(in crate::replay) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) raw: Option<ReplayBodyCapture>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(in crate::replay) struct ReplayBodyCapture {
    pub(in crate::replay) encoding: String,
    pub(in crate::replay) data: String,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct StatementMetadata {
    pub(in crate::replay) param_count: usize,
    pub(in crate::replay) columns: Vec<RecordedMysqlColumn>,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedStatement {
    pub(in crate::replay) sql: String,
    pub(in crate::replay) param_count: usize,
    pub(in crate::replay) last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct BoundParamType {
    pub(in crate::replay) type_code: u8,
    pub(in crate::replay) unsigned: bool,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::replay) enum ResultRowEncoding {
    Text,
    Binary,
}

impl PartialEq for RecordedMysqlResponse {
    fn eq(&self, other: &Self) -> bool {
        self.wire_prefix == other.wire_prefix
            && self.server_status == other.server_status
            && self.status == other.status
            && self.error_code == other.error_code
            && self.error_message == other.error_message
            && self.affected_rows == other.affected_rows
            && self.last_insert_id == other.last_insert_id
            && self.columns == other.columns
            && self.rows == other.rows
            && self.rows_truncated == other.rows_truncated
    }
}
