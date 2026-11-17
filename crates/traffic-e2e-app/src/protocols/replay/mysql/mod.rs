//! Historical recording DTO aliases. Native behavior belongs to the protocol library.
pub(crate) mod sql_match;
pub(crate) use traffic_protocol_mysql::model::MysqlValue as RecordedMysqlValue;
pub(crate) type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
