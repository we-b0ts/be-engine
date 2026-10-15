//! Classify optional setup and cleanup from immutable session evidence.
//! Keep every exchange; only the final unused-dependency requirement changes.
use super::*;
use crate::replay::dependencies::DependencyRecord;
use std::collections::{BTreeMap, BTreeSet};

mod autocommit;
mod read;

/// Only the ends of complete Global read spans are retained. Cases never
/// contribute prefixes, so lazy case loading cannot change another case's proof.
#[derive(Debug, Default)]
pub(in crate::replay) struct ReadPrefixes(BTreeMap<(Uuid, u64), ReadPrefix>);

#[derive(Debug)]
struct ReadPrefix {
    identity: MysqlDependencyIdentity,
    status: u16,
}

pub(in crate::replay) fn classify(
    records: &[DependencyRecord],
    source: ReplaySource,
    global_prefixes: &mut ReadPrefixes,
) -> BTreeMap<usize, OptionalSessionExchange> {
    if source == ReplaySource::Global {
        global_prefixes.0.clear();
    }
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
    let mut optional = BTreeMap::new();
    // Classification happens once per loaded file. Borrow SQL already owned
    // by the records and drop this parse-result cache with the classification.
    let mut read_sql = HashMap::<&str, read::Effect>::new();
    for (connection, exchanges) in connections {
        if ambiguous.contains(&connection) {
            continue;
        }
        let mut read_only = false;
        for (&sequence, &(index, current)) in &exchanges {
            let first = exchanges
                .first_key_value()
                .is_some_and(|(seq, _)| *seq == sequence);
            let previous = sequence.checked_sub(1).and_then(|seq| exchanges.get(&seq));
            let consecutive = previous.is_some_and(|(_, previous)| {
                identity_from_exchange(current).is_some_and(|identity| {
                    identity_from_exchange(previous).as_ref() == Some(&identity)
                })
            });
            let status_continuous = consecutive
                && previous.is_some_and(|(_, previous)| {
                    status_after(previous)
                        .zip(current.server_status_before)
                        .is_some_and(|(after, before)| after & 0x200b == before & 0x200b)
                });
            let local_read = read_only && status_continuous;
            let foreign_read = source == ReplaySource::Case
                && first
                && global_prefixes
                    .0
                    .get(&(connection, sequence))
                    .is_some_and(|prefix| {
                        identity_from_exchange(current).as_ref() == Some(&prefix.identity)
                            && current
                                .server_status_before
                                .is_some_and(|before| before & 0x200b == prefix.status & 0x200b)
                    });
            let continued_read = local_read || foreign_read;
            // The first SQL on this case's connection cannot close a transaction
            // started by its other SQL. ROLLBACK discards an external tail; an
            // unknown COMMIT might persist writes and is deliberately excluded.
            let foreign_rollback = source == ReplaySource::Case
                && first
                && identity_from_exchange(current).is_some()
                && current
                    .server_status_before
                    .is_some_and(|before| before & 0x2008 == 0);
            if successful_end(current, &["rollback"])
                && (continued_read
                    || foreign_rollback
                    || consecutive
                        && previous.is_some_and(|(_, previous)| {
                            successful_end(previous, &["commit", "rollback"])
                        }))
            {
                optional.insert(index, OptionalSessionExchange::Rollback);
            }
            if continued_read && successful_end(current, &["commit"]) {
                optional.insert(index, OptionalSessionExchange::Commit);
            }
            read_only = continued_read && successful_prepare(current)
                || (continued_read
                    || current
                        .server_status_before
                        .is_some_and(|flags| flags & 0x2009 == 0)
                        && (!consecutive || status_continuous))
                    && complete_read(current)
                    && current.sql.as_deref().is_some_and(|sql| {
                        *read_sql.entry(sql).or_insert_with(|| read::classify(sql))
                            == read::Effect::ReadOnly
                    });
            if source == ReplaySource::Global
                && read_only
                && let Some(next) = sequence.checked_add(1)
                && !exchanges.contains_key(&next)
                && let Some(identity) = identity_from_exchange(current)
                && let Some(status) = status_after(current)
            {
                global_prefixes
                    .0
                    .insert((connection, next), ReadPrefix { identity, status });
            }
        }
        autocommit::classify(&exchanges, &mut read_sql, &mut optional);
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
        && exchange.response.valid_row_widths()
}

fn successful_end(exchange: &RecordedMysqlExchange, commands: &[&str]) -> bool {
    successful_control(exchange)
        && exchange.sql.as_deref().is_some_and(|sql| {
            let sql = sql.trim().strip_suffix(';').unwrap_or(sql.trim()).trim();
            commands
                .iter()
                .any(|command| sql.eq_ignore_ascii_case(command))
        })
}

fn successful_control(exchange: &RecordedMysqlExchange) -> bool {
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
        && exchange.response.no_rows()
        && exchange.response.columns.is_empty()
        && exchange.params.as_ref().is_none_or(Vec::is_empty)
}

#[cfg(test)]
mod tests;
