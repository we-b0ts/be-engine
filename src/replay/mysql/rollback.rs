//! Compatibility for redundant rollback after a proven transaction boundary.
//! No inference is made from an ORM name or a SELECT-only request.
use super::*;
use crate::replay::dependencies::DependencyRecord;
use std::collections::{BTreeMap, BTreeSet};

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
    for (connection, exchanges) in connections {
        if ambiguous.contains(&connection) {
            continue;
        }
        for (&sequence, &(index, current)) in &exchanges {
            let previous = sequence.checked_sub(1).and_then(|seq| exchanges.get(&seq));
            let Some((_, previous)) = previous else {
                continue;
            };
            if successful_end(current, &["rollback"])
                && successful_end(previous, &["commit", "rollback"])
                && let Some(identity) = identity_from_exchange(current)
                && identity_from_exchange(previous).as_ref() == Some(&identity)
            {
                optional.insert(index);
            }
        }
    }
    optional
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
