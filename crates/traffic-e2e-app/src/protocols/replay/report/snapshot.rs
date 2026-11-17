//! Native session snapshots preserve their historical report fields.
use super::*;
use serde::Serialize;
use serde_json::Value;
use traffic_replay::report::SessionSnapshot;

#[derive(Debug, Serialize)]
pub(crate) struct NativeSnapshot {
    pub(crate) http_ingress: Value,
    pub(crate) mysql_transaction_semantics: &'static str,
    pub(crate) connections: usize,
    pub(crate) connection_events: Vec<Value>,
    pub(crate) builtin_query_count: usize,
    pub(crate) builtin_queries: Vec<Value>,
    pub(crate) matched_query_count: usize,
    pub(crate) matched_queries: Vec<Value>,
    pub(crate) unmatched_queries: Vec<Value>,
    pub(crate) unsupported_commands: Vec<Value>,
    pub(crate) metadata_warnings: Vec<String>,
    pub(crate) unused_global_exchanges: Vec<Value>,
    pub(crate) unused_global_exchange_count: usize,
    pub(crate) unused_case_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) process_owned_mysql_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) global_mysql_transaction_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_rollback_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_commit_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_autocommit_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_connection_read_committed_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) transaction_equivalent_mysql_autocommit_exchanges: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) mysql_isolation_equivalence: Vec<Value>,
    pub(crate) matched_http_exchange_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) cancelled_http_streams: Vec<Value>,
    pub(crate) matched_http_exchanges: Vec<Value>,
    pub(crate) unmatched_http_requests: Vec<Value>,
    pub(crate) unsupported_http_exchanges: Vec<Value>,
    pub(crate) http_request_header_mismatches: Vec<Value>,
    pub(crate) http_request_header_observations: Vec<Value>,
    pub(crate) http_request_header_observation_count: usize,
    pub(crate) unused_global_http_exchanges: Vec<Value>,
    pub(crate) unused_global_http_exchange_count: usize,
    pub(crate) unused_case_http_exchanges: Vec<Value>,
    pub(crate) allowed_unused_case_http_exchanges: Vec<Value>,
    pub(crate) http_ignored_query_params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allowed_unused_http: Option<ReplayAllowedUnusedHttpReport>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReplayAllowedUnusedHttpReport {
    pub(crate) config: String,
    pub(crate) hosts: Vec<String>,
}

impl RuntimeState<ReplayProtocols> {
    pub(crate) fn native_report_snapshot(&self) -> NativeSnapshot {
        NativeSnapshot {
            http_ingress: serde_json::json!({"omitted":0,"pending":0,"observations":[]}),
            mysql_transaction_semantics: "finite_native_v1",
            connections: 0,
            connection_events: Vec::new(),
            builtin_query_count: 0,
            builtin_queries: Vec::new(),
            matched_query_count: 0,
            matched_queries: Vec::new(),
            unmatched_queries: Vec::new(),
            unsupported_commands: Vec::new(),
            metadata_warnings: Vec::new(),
            unused_global_exchanges: Vec::new(),
            unused_global_exchange_count: 0,
            unused_case_exchanges: Vec::new(),
            process_owned_mysql_exchanges: Vec::new(),
            global_mysql_transaction_exchanges: Vec::new(),
            allowed_unused_mysql_rollback_exchanges: Vec::new(),
            allowed_unused_mysql_commit_exchanges: Vec::new(),
            allowed_unused_mysql_autocommit_exchanges: Vec::new(),
            allowed_unused_mysql_connection_read_committed_exchanges: Vec::new(),
            transaction_equivalent_mysql_autocommit_exchanges: Vec::new(),
            mysql_isolation_equivalence: Vec::new(),
            matched_http_exchange_count: 0,
            cancelled_http_streams: Vec::new(),
            matched_http_exchanges: Vec::new(),
            unmatched_http_requests: Vec::new(),
            unsupported_http_exchanges: Vec::new(),
            http_request_header_mismatches: Vec::new(),
            http_request_header_observations: Vec::new(),
            http_request_header_observation_count: 0,
            unused_global_http_exchanges: Vec::new(),
            unused_global_http_exchange_count: 0,
            unused_case_http_exchanges: Vec::new(),
            allowed_unused_case_http_exchanges: Vec::new(),
            http_ignored_query_params: Vec::new(),
            allowed_unused_http: None,
        }
    }
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
