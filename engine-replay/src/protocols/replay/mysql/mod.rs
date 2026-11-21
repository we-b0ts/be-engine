//! Historical recording DTO aliases. Native behavior belongs to the protocol library.
pub mod sql_match;
pub use traffic_protocol_mysql::model::MysqlValue as RecordedMysqlValue;
pub type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
