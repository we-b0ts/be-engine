use super::super::*;

#[derive(Debug, Serialize)]
pub(in crate::replay) struct ReplayReport {
    pub(in crate::replay) version: u8,
    pub(in crate::replay) mode: ReplayMode,
    pub(in crate::replay) dns_listen: String,
    pub(in crate::replay) tcp_listen: String,
    pub(in crate::replay) case_dir: String,
    pub(in crate::replay) case_dependencies_path: String,
    pub(in crate::replay) active_case_id: Option<String>,
    pub(in crate::replay) cases: Vec<ReplayCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) bootstrap_dependencies_path: Option<String>,
    pub(in crate::replay) targets: Vec<ReplayTarget>,
    pub(in crate::replay) connections: usize,
    pub(in crate::replay) connection_events: Vec<ConnectionReport>,
    pub(in crate::replay) builtin_queries: Vec<QueryReport>,
    pub(in crate::replay) matched_queries: Vec<MatchedQueryReport>,
    pub(in crate::replay) unmatched_queries: Vec<QueryReport>,
    pub(in crate::replay) unsupported_commands: Vec<QueryReport>,
    pub(in crate::replay) metadata_warnings: Vec<String>,
    pub(in crate::replay) unused_bootstrap_exchanges: Vec<RecordedExchangeSummary>,
    pub(in crate::replay) unused_case_exchanges: Vec<RecordedExchangeSummary>,
    pub(in crate::replay) matched_http_exchanges: Vec<http::MatchedHttpExchangeReport>,
    pub(in crate::replay) unmatched_http_requests: Vec<http::HttpRequestReport>,
    pub(in crate::replay) unsupported_http_exchanges: Vec<http::HttpRequestReport>,
    pub(in crate::replay) unused_bootstrap_http_exchanges: Vec<http::RecordedHttpExchangeSummary>,
    pub(in crate::replay) unused_case_http_exchanges: Vec<http::RecordedHttpExchangeSummary>,
    #[serde(flatten)]
    pub(in crate::replay) protocols: ProtocolsReport,
    pub(in crate::replay) ca_cert_path: String,
    pub(in crate::replay) http_ignored_query_params: Vec<String>,
}

impl ReplayReport {
    pub(in crate::replay) fn is_dirty(&self) -> bool {
        !self.unmatched_queries.is_empty()
            || !self.unsupported_commands.is_empty()
            || !self.unused_case_exchanges.is_empty()
            || !self.unused_bootstrap_exchanges.is_empty()
            || !self.unmatched_http_requests.is_empty()
            || !self.unsupported_http_exchanges.is_empty()
            || !self.unused_case_http_exchanges.is_empty()
            || !self.unused_bootstrap_http_exchanges.is_empty()
            || self.protocols.redis.is_dirty()
            || self.protocols.memcached.is_dirty()
            || self.protocols.kafka.is_dirty()
    }

    pub(in crate::replay) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.unmatched_queries
            .iter()
            .any(|query| query.case_id.as_deref() == Some(case_id))
            || self
                .unsupported_commands
                .iter()
                .any(|query| query.case_id.as_deref() == Some(case_id))
            || self
                .unused_case_exchanges
                .iter()
                .any(|exchange| exchange.case_id.as_deref() == Some(case_id))
            || self
                .unmatched_http_requests
                .iter()
                .any(|request| request.case_id.as_deref() == Some(case_id))
            || self
                .unsupported_http_exchanges
                .iter()
                .any(|request| request.case_id.as_deref() == Some(case_id))
            || self
                .unused_case_http_exchanges
                .iter()
                .any(|exchange| exchange.case_id.as_deref() == Some(case_id))
            || self.protocols.redis.case_is_dirty(case_id)
            || self.protocols.memcached.case_is_dirty(case_id)
            || self.protocols.kafka.case_is_dirty(case_id)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub(in crate::replay) struct ProtocolsReport {
    pub(in crate::replay) redis: report::command::CommandProtocolReport,
    pub(in crate::replay) memcached: report::command::CommandProtocolReport,
    pub(in crate::replay) kafka: kafka::KafkaProtocolReport,
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
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct MatchedQueryReport {
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
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct RecordedExchangeSummary {
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
    pub(in crate::replay) sql: Option<String>,
    pub(in crate::replay) status: String,
}
