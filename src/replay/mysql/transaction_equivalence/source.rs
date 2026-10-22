//! Prove complete, ordinary implicit transactions from one immutable input file.
use super::*;
use crate::replay::dependencies::DependencyRecord;

pub(in crate::replay) struct Plan {
    pub setups: Vec<usize>,
    pub transactions: Result<Vec<Vec<usize>>, &'static str>,
}

pub(super) fn prepare(
    records: &[DependencyRecord],
    optional: &BTreeMap<usize, OptionalSessionExchange>,
) -> Vec<Plan> {
    let mut connections = BTreeMap::<Uuid, Vec<(usize, &RecordedMysqlExchange)>>::new();
    let mut unidentified = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if let DependencyRecord::MysqlExchange(record) = record {
            if let Some(connection) = record.connection_id {
                connections
                    .entry(connection)
                    .or_default()
                    .push((index, record));
            } else if is_setup(record) && !optional.contains_key(&index) {
                unidentified.push(Plan {
                    setups: vec![index],
                    transactions: Err("source_connection_missing"),
                });
            }
        }
    }
    for mut records in connections.into_values() {
        let setups: Vec<_> = records
            .iter()
            .filter(|(index, r)| is_setup(r) && !optional.contains_key(index))
            .map(|(i, _)| *i)
            .collect();
        if setups.is_empty() {
            continue;
        }
        records.sort_by_key(|(_, record)| record.query_sequence);
        unidentified.push(Plan {
            setups,
            transactions: transactions(&records),
        });
    }
    unidentified
}

fn is_setup(record: &RecordedMysqlExchange) -> bool {
    matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        && record
            .sql
            .as_deref()
            .and_then(crate::mysql::autocommit::assignment)
            == Some(false)
}

fn transactions(
    records: &[(usize, &RecordedMysqlExchange)],
) -> Result<Vec<Vec<usize>>, &'static str> {
    let mut complete = Vec::new();
    let mut active = Vec::new();
    let mut previous: Option<&RecordedMysqlExchange> = None;
    let mut writes = false;
    for &(index, record) in records {
        let identity = identity_from_exchange(record).ok_or("source_identity_missing")?;
        let sequence = record.query_sequence.ok_or("source_sequence_missing")?;
        let before = record.server_status_before.ok_or("source_status_missing")?;
        let after = if optional_session::successful_prepare(record) {
            before
        } else {
            record
                .response
                .server_status
                .ok_or("source_status_missing")?
        };
        if let Some(previous) = previous {
            if identity_from_exchange(previous).as_ref() != Some(&identity) {
                return Err("source_identity_changed");
            }
            let last = previous.query_sequence.ok_or("source_sequence_missing")?;
            let last_status = if optional_session::successful_prepare(previous) {
                previous.server_status_before
            } else {
                previous.response.server_status
            }
            .ok_or("source_status_missing")?;
            if last_status & 0x200b != before & 0x200b {
                return Err("source_status_discontinuous");
            }
            if sequence <= last || (last.checked_add(1) != Some(sequence) && before & 0x2009 != 0) {
                return Err("source_sequence_gap");
            }
        } else if before & 0x2009 != 0 {
            return Err("source_transaction_start_unknown");
        }
        if is_setup(record) {
            if !optional_session::successful_control(record)
                || before & 0x2009 != 0
                || after & 0x200b != 0
            {
                return Err("source_autocommit_setup_unsafe");
            }
        } else if optional_session::successful_prepare(record)
            || optional_session::successful_ping(record)
        {
            // These commands execute no business SQL, but prove sequence continuity.
        } else if optional_session::successful_end(record, &["commit", "rollback"]) {
            if !active.is_empty() {
                active.push(index);
                complete.push(std::mem::take(&mut active));
            } else if before & 0x2009 != 0 {
                return Err("source_transaction_start_unknown");
            }
        } else {
            let kind = statement(record).ok_or("source_statement_or_response_unsupported")?;
            if before & 2 != 0 || after & 0x200b != 1 || (active.is_empty() && before & 0x2009 != 0)
            {
                return Err("source_transaction_status_unsupported");
            }
            writes |= kind;
            active.push(index);
        }
        previous = Some(record);
    }
    if !active.is_empty() {
        return Err("source_transaction_unclosed");
    }
    if complete.is_empty() || !writes {
        return Err("source_write_transaction_not_proven");
    }
    Ok(complete)
}

/// Return whether a complete supported statement writes transactional data.
fn statement(record: &RecordedMysqlExchange) -> Option<bool> {
    let sql = record.sql.as_deref()?;
    if sql.len() > 1024 * 1024 {
        return None;
    }
    if optional_session::complete_read(record)
        && optional_session::read::classify(sql) == optional_session::read::Effect::ReadOnly
    {
        return Some(false);
    }
    if !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || record.response.status != "ok"
        || record.response.error_code.is_some()
        || record.response.error_message.is_some()
        || record.response.affected_rows.is_none()
        || record.response.rows_truncated
        || !record.response.no_rows()
        || !record.response.columns.is_empty()
    {
        return None;
    }
    let tokens = crate::mysql::sql::tokens(sql)?;
    if optional_session::read::has_session_effect(&tokens) {
        return None;
    }
    let first = tokens.first()?;
    (["insert", "update", "delete", "replace"]
        .iter()
        .any(|name| first.is(name))
        && optional_session::read::classify(sql) == optional_session::read::Effect::StateChange)
        .then_some(true)
}
