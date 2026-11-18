use super::*;
use traffic_engine::protocols::replay::report::snapshot::NativeSnapshot;
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
