use super::*;
use crate::session_setup::is_mysql_session_setup_sql;

/// Retained driver observations keep their native builtin owner. They neither
/// create finite SQL obligations nor invalidate later proven transactions.
pub fn is_nonsemantic_session_setup<E>(record: &RecordedMysqlExchange<E>) -> bool {
    record
        .capture
        .as_ref()
        .is_some_and(|capture| !capture.semantic_required)
        && !record.lifecycle_cleanup
        && record
            .sql
            .as_deref()
            .is_some_and(is_mysql_session_setup_sql)
        && successful_control(record)
        && record.response.server_status.is_some_and(|after| {
            record
                .server_status_before
                .map_or(record.query_sequence == Some(1), |before| {
                    before & 0x200b == after & 0x200b
                })
        })
}
