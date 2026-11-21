//! Complete native session and savepoint observations.
use super::*;
use crate::isolation::Scope;

pub fn isolation_successful<E>(record: &RecordedMysqlExchange<E>) -> bool {
    !record.lifecycle_cleanup
        && record.outcome == traffic_model::DependencyExchangeOutcome::Response
        && record.parse_warnings.is_empty()
        && record.params.as_ref().is_none_or(Vec::is_empty)
        && record.response.error_code.is_none()
        && record.response.error_message.is_none()
        && !record.response.rows_truncated
        && record.response.valid_row_widths()
}

pub fn isolation_control<E>(record: &RecordedMysqlExchange<E>) -> bool {
    isolation_successful(record)
        && record.command == "COM_QUERY"
        && record.response.status == "ok"
        && record.response.affected_rows == Some(0)
        && record.response.last_insert_id == Some(0)
        && record.response.columns.is_empty()
        && record.response.no_rows()
}

pub fn isolation_inactive<E>(record: &RecordedMysqlExchange<E>) -> bool {
    record.server_status_before.is_some_and(|s| s & 0x200b == 0)
        && record
            .response
            .server_status
            .is_some_and(|s| s & 0x200b == 0)
}

pub fn isolation_session_control<E>(record: &RecordedMysqlExchange<E>) -> bool {
    isolation_control(record)
        && isolation_inactive(record)
        && record
            .sql
            .as_deref()
            .and_then(crate::isolation::setting)
            .is_some_and(|(scope, _)| scope == Scope::Session)
}

pub fn complete_savepoint<E>(record: &RecordedMysqlExchange<E>) -> bool {
    matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        && record.outcome == traffic_model::DependencyExchangeOutcome::Response
        && record.parse_warnings.is_empty()
        && record.params.as_ref().is_none_or(Vec::is_empty)
        && record.response.status == "ok"
        && record.response.error_code.is_none()
        && record.response.error_message.is_none()
        && record.response.affected_rows == Some(0)
        && record.response.last_insert_id == Some(0)
        && record.response.no_rows()
        && record.response.columns.is_empty()
        && !record.response.rows_truncated
        && record
            .server_status_before
            .zip(record.response.server_status)
            .is_some_and(|(before, after)| {
                before & 0x2009 == 1 && after & 0x2009 == 1 && before & 2 == after & 2
            })
}
