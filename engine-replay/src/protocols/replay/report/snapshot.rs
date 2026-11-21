//! Native session snapshots preserve their historical report fields.
use serde::Serialize;
use serde_json::Value;
use traffic_replay::report::SessionSnapshot;

#[derive(Debug, Serialize)]
pub struct NativeSnapshot {
    pub http_ingress: Value,
    pub mysql_transaction_semantics: &'static str,
    pub connections: usize,
    pub connection_events: Vec<Value>,
    pub builtin_query_count: usize,
    pub builtin_queries: Vec<Value>,
    pub matched_query_count: usize,
    pub matched_queries: Vec<Value>,
    pub unmatched_queries: Vec<Value>,
    pub unsupported_commands: Vec<Value>,
    pub metadata_warnings: Vec<String>,
    pub unused_global_exchanges: Vec<Value>,
    pub unused_global_exchange_count: usize,
    pub unused_case_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub process_owned_mysql_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub global_mysql_transaction_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_unused_mysql_rollback_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_unused_mysql_commit_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_unused_mysql_autocommit_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_unused_mysql_connection_read_committed_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transaction_equivalent_mysql_autocommit_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mysql_isolation_equivalence: Vec<Value>,
    pub matched_http_exchange_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cancelled_http_streams: Vec<Value>,
    pub matched_http_exchanges: Vec<Value>,
    pub unmatched_http_requests: Vec<Value>,
    pub unsupported_http_exchanges: Vec<Value>,
    pub http_request_header_mismatches: Vec<Value>,
    pub http_request_header_observations: Vec<Value>,
    pub http_request_header_observation_count: usize,
    pub unused_global_http_exchanges: Vec<Value>,
    pub unused_global_http_exchange_count: usize,
    pub unused_case_http_exchanges: Vec<Value>,
    pub allowed_unused_case_http_exchanges: Vec<Value>,
    pub http_ignored_query_params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_unused_http: Option<ReplayAllowedUnusedHttpReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayAllowedUnusedHttpReport {
    pub config: String,
    pub hosts: Vec<String>,
}

impl SessionSnapshot for NativeSnapshot {
    fn is_dirty(&self) -> bool {
        false
    }

    fn unused_run_dependencies(&self) -> std::collections::BTreeMap<String, usize> {
        std::collections::BTreeMap::from([
            ("mysql".into(), self.unused_global_exchange_count),
            ("http".into(), self.unused_global_http_exchange_count),
        ])
    }
    fn unmatched_or_unsafe(&self) -> usize {
        self.unmatched_queries.len()
            + self.unsupported_commands.len()
            + self.unmatched_http_requests.len()
            + self.unsupported_http_exchanges.len()
            + self.http_request_header_mismatches.len()
    }
}
