//! Native session snapshots preserve their historical report fields.
use super::*;
use crate::protocols::replay::mysql;
use serde::Serialize;
use serde_json::Value;
use traffic_replay::ReplaySource;
use traffic_replay::report::SessionSnapshot;

#[derive(Debug, Serialize)]
pub(crate) struct NativeSnapshot {
    pub(crate) http_ingress: Value,
    pub(crate) mysql_transaction_semantics: &'static str,
    pub(crate) connections: usize,
    pub(crate) connection_events: Vec<ConnectionReport>,
    pub(crate) builtin_query_count: usize,
    pub(crate) builtin_queries: Vec<QueryReport>,
    pub(crate) matched_query_count: usize,
    pub(crate) matched_queries: Vec<MatchedQueryReport>,
    pub(crate) unmatched_queries: Vec<QueryReport>,
    pub(crate) unsupported_commands: Vec<QueryReport>,
    pub(crate) metadata_warnings: Vec<String>,
    pub(crate) unused_global_exchanges: Vec<RecordedExchangeSummary>,
    pub(crate) unused_global_exchange_count: usize,
    pub(crate) unused_case_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) process_owned_mysql_exchanges: Vec<mysql::ownership::OwnedExchange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) global_mysql_transaction_exchanges:
        Vec<mysql::transaction_projection::GlobalTransactionExchange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_rollback_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_commit_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_autocommit_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_unused_mysql_connection_read_committed_exchanges:
        Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) transaction_equivalent_mysql_autocommit_exchanges: Vec<RecordedExchangeSummary>,
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

pub(crate) use traffic_protocol_mysql::report::{ConnectionReport, RecordedExchangeSummary};
pub(crate) type QueryReport = traffic_protocol_mysql::report::QueryReport<ReplaySource>;
pub(crate) type MatchedQueryReport =
    traffic_protocol_mysql::report::MatchedQueryReport<ReplaySource>;

impl RuntimeState<ReplayProtocols> {
    pub(crate) fn native_report_snapshot(&self) -> NativeSnapshot {
        NativeSnapshot {
            http_ingress: serde_json::json!({"omitted":0,"pending":0,"observations":[]}),
            mysql_transaction_semantics: "first_write_through_end_v1",
            connections: self.protocol_data().mysql.events.connections,
            connection_events: self.protocol_data().mysql.events.connection_events.clone(),
            builtin_query_count: self.protocol_data().mysql.events.builtin_query_count,
            builtin_queries: self.protocol_data().mysql.events.builtin_queries.clone(),
            matched_query_count: self.protocol_data().mysql.events.matched_query_count,
            matched_queries: self.protocol_data().mysql.events.matched_queries.clone(),
            unmatched_queries: self.protocol_data().mysql.events.unmatched_queries.clone(),
            unsupported_commands: self
                .protocol_data()
                .mysql
                .events
                .unsupported_commands
                .clone(),
            metadata_warnings: self.protocol_data().mysql.events.metadata_warnings.clone(),
            unused_global_exchanges: self.unused_exchanges(ReplaySource::Startup),
            unused_global_exchange_count: self.global_mysql_unused_count(),
            unused_case_exchanges: self.unused_exchanges(ReplaySource::Case),
            process_owned_mysql_exchanges: self.process_owned_mysql(),
            global_mysql_transaction_exchanges: self.global_mysql_transactions(),
            allowed_unused_mysql_rollback_exchanges: self.allowed_unused_rollbacks(),
            allowed_unused_mysql_commit_exchanges: self.allowed_unused_commits(),
            allowed_unused_mysql_autocommit_exchanges: self.allowed_unused_autocommit(),
            allowed_unused_mysql_connection_read_committed_exchanges: self
                .allowed_unused_connection_read_committed(),
            transaction_equivalent_mysql_autocommit_exchanges: self
                .transaction_equivalent_autocommit(),
            mysql_isolation_equivalence: self.protocol_data().mysql.isolation.audit(),
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
        self.unmatched_queries
            .iter()
            .any(|query| query.case_id.is_some())
            || self
                .unsupported_commands
                .iter()
                .any(|query| query.case_id.is_some())
            || !self.unused_case_exchanges.is_empty()
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
