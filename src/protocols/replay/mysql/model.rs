use std::collections::BTreeSet;

use super::*;

#[derive(Debug, Default)]
pub(crate) struct ReplayEvents {
    pub(super) request_order: crate::replay::admission::RequestOrder,
    pub(crate) global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    pub(crate) dirty_case_ids: BTreeSet<String>,
    pub(crate) connections: usize,
    pub(crate) connection_events: Vec<ConnectionReport>,
    pub(crate) builtin_query_count: usize,
    pub(crate) builtin_queries: Vec<QueryReport>,
    pub(crate) builtin_query_details: SuccessDetailBudget,
    pub(crate) matched_query_count: usize,
    pub(crate) matched_queries: Vec<MatchedQueryReport>,
    pub(crate) matched_query_details: SuccessDetailBudget,
    pub(crate) unmatched_queries: Vec<QueryReport>,
    pub(crate) unsupported_commands: Vec<QueryReport>,
    pub(crate) metadata_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayExchange {
    pub(crate) source: ReplaySource,
    pub(crate) case_id: Option<String>,
    pub(crate) identity: MysqlDependencyIdentity,
    pub(crate) record: RecordedMysqlExchange,
    pub(crate) optional_session: Option<OptionalSessionExchange>,
    pub(crate) status: ReplayExchangeStatus,
    pub(crate) timing: ReplayExchangeTiming,
}

pub(crate) use traffic_protocol_mysql::session_control::OptionalSessionExchange;

#[derive(Debug, Clone)]
pub(crate) struct MatchedExchange {
    pub(super) request_observed_at: Option<DateTime<Utc>>,
    pub(super) target_observation_id: Option<String>,
    pub(crate) claim: crate::replay::admission::ClaimTicket,
    pub(crate) hypothesis_owner: Option<crate::policy::runtime::request_contract::RequestContracts>,
    pub(crate) transaction_owner: Option<Option<String>>,
    pub(crate) value_delivery: Option<contracts::PreparedDelivery>,
    pub(crate) time_copy_delivery: Option<contracts::time_copies::PreparedRead>,
    #[allow(dead_code)]
    pub(crate) source: ReplaySource,
    #[allow(dead_code)]
    pub(crate) index: usize,
    pub(crate) record: RecordedMysqlExchange,
    pub(crate) timing: ReplayExchangeTiming,
    pub(crate) report: MatchedQueryReport,
}

pub(crate) use traffic_protocol_mysql::session_identity::{
    DependencyIdentity as MysqlDependencyIdentity, SessionIdentity as ReplaySessionIdentity,
};

pub(crate) type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
pub(crate) type RecordedMysqlResponse =
    traffic_protocol_mysql::recorded::RecordedMysqlResponse<crate::dependency_index::RecordRef>;

pub(crate) use traffic_protocol_mysql::model::{
    MysqlColumn as RecordedMysqlColumn, MysqlValue as RecordedMysqlValue, ResultRowEncoding,
};

pub(crate) use traffic_protocol_mysql::prepare::StatementMetadata;
