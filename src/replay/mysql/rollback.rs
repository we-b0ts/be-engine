//! Classify duplicate rollback and proven implicit read-only session cleanup.
//! Keep every exchange; only the final unused-dependency requirement changes.
use super::*;
use crate::replay::dependencies::DependencyRecord;
use std::collections::{BTreeMap, BTreeSet};

mod read;

pub(in crate::replay) fn optional_rollbacks(records: &[DependencyRecord]) -> BTreeSet<usize> {
    let mut connections = BTreeMap::<Uuid, BTreeMap<u64, (usize, &RecordedMysqlExchange)>>::new();
    let mut ambiguous = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        let DependencyRecord::MysqlExchange(exchange) = record else {
            continue;
        };
        let Some(connection) = exchange.connection_id else {
            continue;
        };
        let Some(sequence) = exchange.query_sequence else {
            ambiguous.insert(connection);
            continue;
        };
        if connections
            .entry(connection)
            .or_default()
            .insert(sequence, (index, exchange))
            .is_some()
        {
            ambiguous.insert(connection);
        }
    }
    let mut optional = BTreeSet::new();
    // Classification happens once per loaded file. Borrow SQL already owned
    // by the records and drop this parse-result cache with the classification.
    let mut read_sql = HashMap::<&str, bool>::new();
    for (connection, exchanges) in connections {
        if ambiguous.contains(&connection) {
            continue;
        }
        let mut read_only = false;
        for (&sequence, &(index, current)) in &exchanges {
            let previous = sequence.checked_sub(1).and_then(|seq| exchanges.get(&seq));
            let consecutive = previous.is_some_and(|(_, previous)| {
                identity_from_exchange(current).is_some_and(|identity| {
                    identity_from_exchange(previous).as_ref() == Some(&identity)
                })
            });
            let continued_read = read_only
                && consecutive
                && previous.is_some_and(|(_, previous)| {
                    status_after(previous)
                        .zip(current.server_status_before)
                        .is_some_and(|(after, before)| after & 0x200b == before & 0x200b)
                });
            if successful_end(current, &["rollback"])
                && (continued_read
                    || consecutive
                        && previous.is_some_and(|(_, previous)| {
                            successful_end(previous, &["commit", "rollback"])
                        }))
            {
                optional.insert(index);
            }
            read_only = continued_read && successful_prepare(current)
                || (continued_read
                    || current
                        .server_status_before
                        .is_some_and(|flags| flags & 0x2009 == 0))
                    && complete_read(current)
                    && current.sql.as_deref().is_some_and(|sql| {
                        *read_sql
                            .entry(sql)
                            .or_insert_with(|| read::plain_select(sql))
                    });
        }
    }
    optional
}

fn successful_prepare(exchange: &RecordedMysqlExchange) -> bool {
    exchange.command == "COM_STMT_PREPARE"
        && exchange.response.status == "stmt_prepare"
        && exchange.outcome == crate::DependencyExchangeOutcome::Response
        && exchange.parse_warnings.is_empty()
        && exchange.response.error_code.is_none()
        && exchange.response.error_message.is_none()
        && exchange
            .server_status_before
            .is_some_and(|flags| flags & 8 == 0)
}

fn status_after(exchange: &RecordedMysqlExchange) -> Option<u16> {
    if successful_prepare(exchange) {
        // PREPARE carries no transaction status and executes no SQL.
        exchange.server_status_before
    } else {
        exchange.response.server_status
    }
}

fn complete_read(exchange: &RecordedMysqlExchange) -> bool {
    matches!(exchange.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        && identity_from_exchange(exchange).is_some()
        && exchange.parse_warnings.is_empty()
        && exchange.outcome == crate::DependencyExchangeOutcome::Response
        && exchange.response.status == "resultset"
        && exchange
            .response
            .server_status
            .is_some_and(|flags| flags & 8 == 0)
        && exchange.response.error_code.is_none()
        && exchange.response.error_message.is_none()
        && !exchange.response.rows_truncated
        && !exchange.response.columns.is_empty()
        && exchange
            .response
            .rows
            .iter()
            .all(|row| row.len() == exchange.response.columns.len())
}

fn successful_end(exchange: &RecordedMysqlExchange, commands: &[&str]) -> bool {
    exchange.command == "COM_QUERY"
        && exchange.parse_warnings.is_empty()
        && exchange.outcome == crate::DependencyExchangeOutcome::Response
        && exchange.response.status == "ok"
        // A bare COMMIT/ROLLBACK can implicitly AND CHAIN via completion_type.
        // Require the server to confirm no transaction and no further results.
        && exchange.response.server_status.is_some_and(|flags| flags & 0x2009 == 0)
        && exchange.response.error_code.is_none()
        && exchange.response.error_message.is_none()
        && exchange.response.affected_rows == Some(0)
        && exchange.response.last_insert_id == Some(0)
        && !exchange.response.rows_truncated
        && exchange.response.rows.is_empty()
        && exchange.response.columns.is_empty()
        && exchange.params.as_ref().is_none_or(Vec::is_empty)
        && exchange.sql.as_deref().is_some_and(|sql| {
            let sql = sql.trim().strip_suffix(';').unwrap_or(sql.trim()).trim();
            commands
                .iter()
                .any(|command| sql.eq_ignore_ascii_case(command))
        })
}

#[cfg(test)]
mod tests;
