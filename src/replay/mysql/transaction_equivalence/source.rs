//! Prove complete Source transaction segments before assigning write obligations.
use super::*;
use crate::replay::dependencies::DependencyRecord;

pub(in crate::replay) struct Plan {
    pub setups: Vec<usize>,
    pub transactions: Vec<Segment>,
    pub reason: Option<&'static str>,
}

pub(in crate::replay) struct Segment {
    pub members: Vec<usize>,
    pub first_write: Option<usize>,
    pub write_count: usize,
    pub explicit: bool,
    pub strict: bool,
}

pub(super) fn prepare(
    records: &[DependencyRecord],
    optional: &BTreeMap<usize, OptionalSessionExchange>,
) -> Vec<Plan> {
    let mut connections = BTreeMap::<Uuid, Vec<(usize, &RecordedMysqlExchange)>>::new();
    let mut plans = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if let DependencyRecord::MysqlExchange(record) = record {
            if let Some(connection) = record.connection_id {
                connections
                    .entry(connection)
                    .or_default()
                    .push((index, record));
            } else if assignment(record).is_some() && !optional.contains_key(&index) {
                plans.push(Plan {
                    setups: vec![index],
                    transactions: Vec::new(),
                    reason: Some("source_connection_missing"),
                });
            }
        }
    }
    for mut records in connections.into_values() {
        let setups = records
            .iter()
            .filter(|(index, r)| assignment(r).is_some() && !optional.contains_key(index))
            .map(|(i, _)| *i)
            .collect();
        records.sort_by_key(|(_, record)| record.query_sequence);
        let mut transactions = Vec::new();
        let reason = collect_transactions(&records, &mut transactions).err();
        plans.push(Plan {
            setups,
            transactions,
            reason,
        });
    }
    plans
}

fn assignment(record: &RecordedMysqlExchange) -> Option<bool> {
    matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        .then(|| {
            record
                .sql
                .as_deref()
                .and_then(crate::mysql::autocommit::assignment)
        })
        .flatten()
}

fn collect_transactions(
    records: &[(usize, &RecordedMysqlExchange)],
    complete: &mut Vec<Segment>,
) -> Result<(), &'static str> {
    // Duplicate wire identities can make an already collected end ambiguous.
    // Check them before retaining any partial connection proof.
    if records
        .windows(2)
        .any(|pair| pair[0].1.query_sequence == pair[1].1.query_sequence)
    {
        return Err("source_sequence_ambiguous");
    }
    let mut active = Vec::<(usize, bool, bool)>::new();
    let mut explicit = false;
    let mut previous: Option<(&RecordedMysqlExchange, u16)> = None;
    for (position, &(index, record)) in records.iter().enumerate() {
        let identity = identity_from_exchange(record).ok_or("source_identity_missing")?;
        let sequence = record.query_sequence.ok_or("source_sequence_missing")?;
        let before = record.server_status_before.ok_or("source_status_missing")?;
        let failed_update = update_outcome(record) == Some("error");
        let after = status_after(record)
            .or_else(|| {
                let (_, next) = records.get(position + 1)?;
                (failed_update
                    && next.query_sequence == sequence.checked_add(1)
                    && identity_from_exchange(next).as_ref() == Some(&identity))
                .then_some(next.server_status_before)
                .flatten()
            })
            .ok_or("source_status_missing")?;
        if let Some((previous, last_status)) = previous {
            if identity_from_exchange(previous).as_ref() != Some(&identity) {
                return Err("source_identity_changed");
            }
            let last = previous.query_sequence.ok_or("source_sequence_missing")?;
            if last_status & 0x200b != before & 0x200b {
                return Err("source_status_discontinuous");
            }
            if sequence <= last || (last.checked_add(1) != Some(sequence) && before & 0x2009 != 0) {
                return Err("source_sequence_gap");
            }
        } else if before & 0x2009 != 0 {
            return Err("source_transaction_start_unknown");
        }
        if let Some(enabled) = assignment(record) {
            if !optional_session::successful_control(record)
                || before & 0x2009 != 0
                || after & 0x200b != if enabled { 2 } else { 0 }
                || !active.is_empty()
            {
                return Err("source_autocommit_setup_unsafe");
            }
        } else if optional_session::successful_prepare(record)
            || optional_session::successful_ping(record)
        {
            // Neither command executes business SQL; both preserve continuity.
        } else if optional_session::successful_begin(record) {
            if !active.is_empty() {
                return Err("source_transaction_restarted");
            }
            active.push((index, false, false));
            explicit = true;
        } else if optional_session::successful_end(record, &["commit", "rollback"]) {
            if active.is_empty() && before & 0x2009 != 0 {
                return Err("source_transaction_start_unknown");
            }
            if !active.is_empty() {
                let first_write = active.iter().position(|(_, write, _)| *write);
                let write_count = active.iter().filter(|(_, write, _)| *write).count();
                let strict = active.iter().any(|(_, _, strict)| *strict);
                let mut members = active.drain(..).map(|(i, _, _)| i).collect::<Vec<_>>();
                members.push(index);
                complete.push(Segment {
                    members,
                    first_write,
                    write_count,
                    explicit,
                    strict,
                });
            }
            explicit = false;
        } else {
            let (write, strict) =
                statement(record).ok_or("source_statement_or_response_unsupported")?;
            if before & 0x200b == 2 && after & 0x200b == 2 && active.is_empty() {
                // Source-native autocommit statements have no cross-statement obligation.
            } else {
                if (!failed_update && after & 0x2009 != 1)
                    || (failed_update && after & 0x2008 != 0)
                    || before & 2 != after & 2
                    || (active.is_empty() && before & 0x2009 != 0)
                {
                    return Err("source_transaction_status_unsupported");
                }
                active.push((index, write, strict));
            }
        }
        previous = Some((record, after));
    }
    if !active.is_empty() {
        return Err("source_transaction_unclosed");
    }
    Ok(())
}

fn status_after(record: &RecordedMysqlExchange) -> Option<u16> {
    if optional_session::successful_prepare(record) {
        record.server_status_before
    } else {
        record.response.server_status
    }
}

/// DML count is a request property; an UPDATE affecting zero rows is still a write.
fn statement(record: &RecordedMysqlExchange) -> Option<(bool, bool)> {
    let sql = record.sql.as_deref()?;
    if sql.len() > 1024 * 1024 {
        return None;
    }
    if update_outcome(record) == Some("error") {
        return Some((true, false));
    }
    if optional_session::complete_read(record)
        && optional_session::read::classify(sql) == optional_session::read::Effect::ReadOnly
    {
        return Some((false, false));
    }
    if !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || !matches!(record.response.status.as_str(), "ok" | "resultset")
        || record.response.error_code.is_some()
        || record.response.error_message.is_some()
        || record.response.rows_truncated
    {
        return None;
    }
    if record.response.status == "resultset" && !optional_session::complete_read(record) {
        return None;
    }
    let tokens = crate::mysql::sql::tokens(sql);
    let write = tokens
        .as_ref()
        .and_then(|t| t.first())
        .is_some_and(|first| {
            ["insert", "update", "delete", "replace"]
                .iter()
                .any(|name| first.is(name))
        });
    let ordinary_write = write
        && record.response.status == "ok"
        && record.response.affected_rows.is_some()
        && record.response.no_rows()
        && record.response.columns.is_empty()
        && tokens
            .as_ref()
            .is_some_and(|t| !optional_session::read::has_session_effect(t))
        && optional_session::read::classify(sql) == optional_session::read::Effect::StateChange;
    // Unknown SQL and locking reads retain a complete same-socket transaction.
    Some((write, !ordinary_write))
}

/// Only ordinary UPDATE outcomes authorize the narrow no-effect rollback exception.
pub(super) fn update_outcome(record: &RecordedMysqlExchange) -> Option<&'static str> {
    let sql = record.sql.as_deref()?;
    if sql.len() > 1024 * 1024
        || !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || record.response.rows_truncated
        || !record.response.no_rows()
        || !record.response.columns.is_empty()
    {
        return None;
    }
    let tokens = crate::mysql::sql::tokens(sql)?;
    if !tokens.first()?.is("update")
        || optional_session::read::has_session_effect(&tokens)
        || optional_session::read::classify(sql) != optional_session::read::Effect::StateChange
    {
        return None;
    }
    if record.response.status == "error" && record.response.error_code.is_some() {
        return Some("error");
    }
    if record.response.status != "ok"
        || record.response.error_code.is_some()
        || record.response.error_message.is_some()
    {
        return None;
    }
    Some(if record.response.affected_rows? == 0 {
        "zero_affected_rows"
    } else {
        "positive_affected_rows"
    })
}
