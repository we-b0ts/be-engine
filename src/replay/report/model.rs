use super::super::*;

#[derive(Debug, Serialize)]
pub(in crate::replay) struct ReplayReport {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) dependency_pre_matches: Vec<crate::value_contract::pre_match::Candidate>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) case_execution_failures: Vec<Value>,
    pub(in crate::replay) connect_failures: connect_failure::Report,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) policy_witnesses: Option<crate::policy_evidence::WitnessManifest>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) egress_rejections: Vec<ReplayEgressRejections>,
    pub(in crate::replay) version: u8,
    pub(in crate::replay) mysql_transaction_semantics: &'static str,
    pub(in crate::replay) session_id: String,
    pub(in crate::replay) started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) finalized_at: Option<DateTime<Utc>>,
    pub(in crate::replay) finalized: bool,
    pub(in crate::replay) mode: ReplayMode,
    pub(in crate::replay) dns_listen: String,
    pub(in crate::replay) tcp_listen: String,
    pub(in crate::replay) case_dir: String,
    pub(in crate::replay) case_dependencies_path: String,
    pub(in crate::replay) active_case_id: Option<String>,
    pub(in crate::replay) cases: Vec<ReplayCaseReport>,
    pub(in crate::replay) selected_case_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) global_dependencies_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) recording_network_path: Option<String>,
    pub(in crate::replay) targets: Vec<ReplayTarget>,
    pub(in crate::replay) unrecorded_targets: Vec<UnrecordedTargetReport>,
    pub(in crate::replay) success_detail_limit: usize,
    pub(in crate::replay) success_detail_scope: &'static str,
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) connection_events: Vec<ConnectionReport>,
    pub(in crate::replay) builtin_query_count: usize,
    pub(in crate::replay) builtin_queries: Vec<QueryReport>,
    pub(in crate::replay) matched_query_count: usize,
    pub(in crate::replay) matched_queries: Vec<MatchedQueryReport>,
    pub(in crate::replay) unmatched_queries: Vec<QueryReport>,
    pub(in crate::replay) unsupported_commands: Vec<QueryReport>,
    pub(in crate::replay) metadata_warnings: Vec<String>,
    pub(in crate::replay) unused_global_exchanges: Vec<RecordedExchangeSummary>,
    pub(in crate::replay) unused_global_exchange_count: usize,
    pub(in crate::replay) unused_case_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) process_owned_mysql_exchanges: Vec<mysql::ownership::OwnedExchange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) global_mysql_transaction_exchanges:
        Vec<mysql::transaction_projection::GlobalTransactionExchange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) allowed_unused_mysql_rollback_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) allowed_unused_mysql_commit_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) allowed_unused_mysql_autocommit_exchanges: Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) transaction_equivalent_mysql_autocommit_exchanges:
        Vec<RecordedExchangeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) mysql_isolation_equivalence: Vec<Value>,
    pub(in crate::replay) matched_http_exchange_count: usize,
    pub(in crate::replay) matched_http_exchanges: Vec<http::MatchedHttpExchangeReport>,
    pub(in crate::replay) unmatched_http_requests: Vec<http::HttpRequestReport>,
    pub(in crate::replay) unsupported_http_exchanges: Vec<http::HttpRequestReport>,
    pub(in crate::replay) http_request_header_mismatches: Vec<http::HeaderDifferenceReport>,
    pub(in crate::replay) http_request_header_observations: Vec<http::HeaderDifferenceReport>,
    pub(in crate::replay) http_request_header_observation_count: usize,
    pub(in crate::replay) unused_global_http_exchanges: Vec<http::RecordedHttpExchangeSummary>,
    pub(in crate::replay) unused_global_http_exchange_count: usize,
    pub(in crate::replay) unused_case_http_exchanges: Vec<http::RecordedHttpExchangeSummary>,
    pub(in crate::replay) allowed_unused_case_http_exchanges:
        Vec<http::RecordedHttpExchangeSummary>,
    #[serde(flatten)]
    pub(in crate::replay) protocols: ProtocolsReport,
    pub(in crate::replay) ca_cert_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) replay_policy: Option<ReplayPolicyReport>,
    pub(in crate::replay) http_ignored_query_params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) allowed_unused_http: Option<ReplayAllowedUnusedHttpReport>,
}

impl ReplayReport {
    pub(in crate::replay) fn is_complete(&self) -> bool {
        self.active_case_id.is_none()
            && !self.cases.is_empty()
            && self
                .cases
                .iter()
                .all(|case| case.status == ReplayCaseStatus::Ended)
    }

    pub(in crate::replay) fn is_dirty(&self) -> bool {
        !self.dependency_pre_matches.is_empty()
            || !self.case_execution_failures.is_empty()
            || self.connect_failures.is_dirty()
            || !self.unrecorded_targets.is_empty()
            || self
                .unmatched_queries
                .iter()
                .any(|query| query.case_id.is_some())
            || self
                .unsupported_commands
                .iter()
                .any(|query| query.case_id.is_some())
            || !self.unused_case_exchanges.is_empty()
            || self
                .unmatched_http_requests
                .iter()
                .any(|request| request.case_id.is_some())
            || self
                .unsupported_http_exchanges
                .iter()
                .any(|request| request.case_id.is_some())
            || !self.unused_case_http_exchanges.is_empty()
            || self
                .http_request_header_mismatches
                .iter()
                .any(|event| event.case_id.is_some())
            || self.protocols.redis.is_dirty()
            || self.protocols.memcached.is_dirty()
            || self.protocols.kafka.is_dirty()
            || self.protocols.motan.is_dirty()
            || self
                .replay_policy
                .as_ref()
                .is_some_and(|policy| !policy.unused_applicable_dependency_rule_ids.is_empty())
    }
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct UnrecordedTargetReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) case_id: Option<String>,
    pub(in crate::replay) target: TargetKey,
    pub(in crate::replay) reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct ReplayAllowedUnusedHttpReport {
    pub(in crate::replay) config: String,
    pub(in crate::replay) hosts: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(in crate::replay) struct ProtocolsReport {
    pub(in crate::replay) redis: report::command::CommandProtocolReport,
    pub(in crate::replay) memcached: report::command::CommandProtocolReport,
    pub(in crate::replay) kafka: kafka::KafkaProtocolReport,
    pub(in crate::replay) motan: report::command::CommandProtocolReport,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct ConnectionReport {
    pub(in crate::replay) peer_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) username: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct QueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) diagnostic: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) username: Option<String>,
    pub(in crate::replay) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) params: Option<Vec<RecordedMysqlValue>>,
    pub(in crate::replay) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) recorded_source: Option<ReplaySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) recorded_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct MatchedQueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) source_connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) source_query_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) username: Option<String>,
    pub(in crate::replay) source: ReplaySource,
    pub(in crate::replay) index: usize,
    pub(in crate::replay) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) params: Option<Vec<RecordedMysqlValue>>,
    pub(in crate::replay) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target_event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct RecordedExchangeSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) diagnostic: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) query_sequence: Option<u64>,
    pub(in crate::replay) index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) username: Option<String>,
    pub(in crate::replay) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) sql_summary: Option<SqlSummary>,
    pub(in crate::replay) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) row_count: Option<usize>,
}

pub(super) fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}
