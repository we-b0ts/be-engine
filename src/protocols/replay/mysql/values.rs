//! Bind native MySQL responses to the framework's immutable evidence references.
use super::RecordedMysqlResponse;
pub(crate) use traffic_protocol_mysql::values::*;

pub(crate) fn builtin_response(sql: &str, database: Option<&str>) -> Option<RecordedMysqlResponse> {
    traffic_protocol_mysql::builtin::builtin_response(sql, database)
}
