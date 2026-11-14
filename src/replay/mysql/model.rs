use std::collections::BTreeSet;

use super::*;

#[derive(Debug, Default)]
pub(in crate::replay) struct ReplayEvents {
    pub(super) request_order: crate::replay::admission::RequestOrder,
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
pub(crate) struct ReplayExchange {
    pub(crate) source: ReplaySource,
    pub(crate) case_id: Option<String>,
    pub(crate) identity: MysqlDependencyIdentity,
    pub(crate) record: RecordedMysqlExchange,
    pub(crate) optional_session: Option<OptionalSessionExchange>,
    pub(crate) status: ReplayExchangeStatus,
    pub(crate) timing: ReplayExchangeTiming,
}

pub(in crate::replay) use traffic_protocol_mysql::session_control::OptionalSessionExchange;

#[derive(Debug, Clone)]
pub(in crate::replay) struct MatchedExchange {
    pub(super) request_observed_at: Option<DateTime<Utc>>,
    pub(super) target_observation_id: Option<String>,
    pub(in crate::replay) claim: crate::replay::admission::ClaimTicket,
    pub(in crate::replay) hypothesis_owner:
        Option<crate::replay::policy::request_contract::RequestContracts>,
    pub(in crate::replay) transaction_owner: Option<Option<String>>,
    pub(in crate::replay) value_delivery: Option<contracts::PreparedDelivery>,
    pub(in crate::replay) time_copy_delivery: Option<contracts::time_copies::PreparedRead>,
    #[allow(dead_code)]
    pub(in crate::replay) source: ReplaySource,
    #[allow(dead_code)]
    pub(in crate::replay) index: usize,
    pub(in crate::replay) record: RecordedMysqlExchange,
    pub(in crate::replay) timing: ReplayExchangeTiming,
    pub(in crate::replay) report: MatchedQueryReport,
}

pub(in crate::replay) use traffic_protocol_mysql::session_identity::{
    DependencyIdentity as MysqlDependencyIdentity, SessionIdentity as ReplaySessionIdentity,
};

pub(in crate::replay) type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
pub(in crate::replay) type RecordedMysqlResponse =
    traffic_protocol_mysql::recorded::RecordedMysqlResponse<crate::dependency_index::RecordRef>;

pub(in crate::replay) use traffic_protocol_mysql::model::{
    MysqlColumn as RecordedMysqlColumn, MysqlValue as RecordedMysqlValue, PreparedStatement,
    ResultRowEncoding, ValueCapture as ReplayBodyCapture,
};

pub(in crate::replay) use traffic_protocol_mysql::prepare::StatementMetadata;
