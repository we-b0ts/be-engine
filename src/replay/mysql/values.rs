//! Bind native MySQL responses to the framework's immutable evidence references.
use super::RecordedMysqlResponse;
pub(in crate::replay) use traffic_protocol_mysql::values::*;

pub(in crate::replay) fn builtin_response(
    sql: &str,
    database: Option<&str>,
) -> Option<RecordedMysqlResponse> {
    traffic_protocol_mysql::builtin::builtin_response(sql, database)
}
