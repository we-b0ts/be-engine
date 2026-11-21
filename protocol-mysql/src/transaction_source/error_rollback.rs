//! A native ERR has no status flags. Its contiguous rollback envelope can still
//! require every original member on one explicit Target transaction.
use super::*;

pub fn prove<E>(
    records: &[(usize, &RecordedMysqlExchange<E>)],
    position: usize,
    active: &[(usize, bool, bool)],
    explicit: bool,
) -> Option<Segment> {
    if active.is_empty() {
        return None;
    }
    let (error_index, error) = *records.get(position)?;
    let (end_index, end) = *records.get(position + 1)?;
    let before = error.server_status_before?;
    let after = status_after(end)?;
    if !failed_dml(error)
        || before & 0x2009 != 1
        || end.server_status_before.is_some()
        || !optional_session::successful_end(end, &["rollback"])
        || before & 2 != after & 2
    {
        return None;
    }
    let identity = identity_from_exchange(error)?;
    let sequence = error.query_sequence?;
    if identity_from_exchange(end)? != identity
        || end.connection_id != error.connection_id
        || end.query_sequence? != sequence.checked_add(1)?
    {
        return None;
    }
    // Recheck the raw interval, including reads before the write. Global-read
    // bridges, skipped controls and missing original commands cannot authorize
    // this recovery. The ordinary scanner already validated each active member.
    let start = position.checked_sub(active.len())?;
    let prefix = records.get(start..position)?;
    let first = prefix.first()?.1;
    if first.server_status_before? & 0x2009 != 0 {
        return None;
    }
    let mut next_sequence = first.query_sequence?;
    let mut next_status = first.server_status_before?;
    for ((index, member), (active_index, _, _)) in prefix.iter().zip(active) {
        if index != active_index
            || member.connection_id != error.connection_id
            || identity_from_exchange(member)? != identity
            || member.query_sequence != Some(next_sequence)
            || member.server_status_before? & 0x200b != next_status & 0x200b
        {
            return None;
        }
        next_sequence = next_sequence.checked_add(1)?;
        next_status = status_after(member)?;
        if next_status & 0x2009 != 1 {
            return None;
        }
    }
    if next_sequence != sequence || next_status & 0x200b != before & 0x200b {
        return None;
    }
    let first_write = active
        .iter()
        .position(|(_, write, _)| *write)
        .unwrap_or(active.len());
    let write_count = active.iter().filter(|(_, write, _)| *write).count() + 1;
    let mut members = active
        .iter()
        .map(|(index, _, _)| *index)
        .collect::<Vec<_>>();
    members.extend([error_index, end_index]);
    Some(Segment {
        members,
        first_write: Some(first_write),
        write_count,
        explicit,
        // No autocommit equivalence, free reads or end omission. The existing
        // delivery witness must retain the whole ordered physical transaction.
        strict: true,
    })
}

fn failed_dml<E>(record: &RecordedMysqlExchange<E>) -> bool {
    let Some(sql) = record.sql.as_deref() else {
        return false;
    };
    if sql.len() > 1024 * 1024
        || !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        || record.outcome != traffic_model::DependencyExchangeOutcome::Response
        || !record.parse_warnings.is_empty()
        || record.response.status != "error"
        || record.response.error_code.is_none()
        || record.response.server_status.is_some()
        || record.response.affected_rows.is_some()
        || record.response.last_insert_id.is_some()
        || record.response.rows_truncated
        || !record.response.no_rows()
        || !record.response.columns.is_empty()
    {
        return false;
    }
    crate::sql::tokens(sql).is_some_and(|tokens| {
        tokens.first().is_some_and(|first| {
            ["insert", "update", "delete", "replace"]
                .iter()
                .any(|word| first.is(word))
        }) && !optional_session::read::has_session_effect(&tokens)
            && optional_session::read::classify(sql) == optional_session::read::Effect::StateChange
    })
}
