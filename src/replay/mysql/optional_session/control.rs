//! Complete zero-effect responses and plain transaction-control statements.
use super::*;

pub(super) fn successful_begin(exchange: &RecordedMysqlExchange) -> bool {
    complete_control(exchange)
        && plain_statement(exchange, &["begin", "start transaction"])
        && exchange
            .server_status_before
            .zip(exchange.response.server_status)
            .is_some_and(|(before, after)| {
                // BEGIN inside an existing transaction can commit its writes.
                before & 0x2009 == 0 && after & 0x2009 == 1 && before & 2 == after & 2
            })
}

pub(in crate::replay::mysql) fn successful_end(
    exchange: &RecordedMysqlExchange,
    commands: &[&str],
) -> bool {
    successful_control(exchange)
        && plain_statement(exchange, commands)
        && exchange.server_status_before.is_none_or(|before| {
            exchange
                .response
                .server_status
                .is_some_and(|after| before & 2 == after & 2)
        })
}

pub(in crate::replay::mysql) fn successful_control(exchange: &RecordedMysqlExchange) -> bool {
    complete_control(exchange)
        // A bare COMMIT/ROLLBACK can implicitly AND CHAIN via completion_type.
        // Require the server to confirm no transaction and no further results.
        && exchange
            .response
            .server_status
            .is_some_and(|flags| flags & 0x2009 == 0)
}

fn plain_statement(exchange: &RecordedMysqlExchange, commands: &[&str]) -> bool {
    exchange.sql.as_deref().is_some_and(|sql| {
        let sql = sql.trim().strip_suffix(';').unwrap_or(sql.trim()).trim();
        commands
            .iter()
            .any(|command| sql.eq_ignore_ascii_case(command))
    })
}

fn complete_control(exchange: &RecordedMysqlExchange) -> bool {
    exchange.command == "COM_QUERY"
        && exchange.parse_warnings.is_empty()
        && exchange.outcome == crate::DependencyExchangeOutcome::Response
        && exchange.response.status == "ok"
        && exchange.response.error_code.is_none()
        && exchange.response.error_message.is_none()
        && exchange.response.affected_rows == Some(0)
        && exchange.response.last_insert_id == Some(0)
        && !exchange.response.rows_truncated
        && exchange.response.no_rows()
        && exchange.response.columns.is_empty()
        && exchange.params.as_ref().is_none_or(Vec::is_empty)
}
