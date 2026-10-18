//! AUTOCOMMIT omission is derived from read-only spans on one loaded connection.
use super::*;

pub(super) fn classify<'a>(
    exchanges: &BTreeMap<u64, (usize, &'a RecordedMysqlExchange)>,
    source: ReplaySource,
    read_sql: &mut HashMap<&'a str, read::Effect>,
    optional: &mut BTreeMap<usize, OptionalSessionExchange>,
) {
    let mut setups = Vec::new();
    let mut previous: Option<(u64, &RecordedMysqlExchange)> = None;
    let mut saw_read = false;
    let mut read_span = false;
    for (&sequence, &(index, current)) in exchanges {
        let Some(identity) = identity_from_exchange(current) else {
            return;
        };
        let Some(before) = current.server_status_before else {
            return;
        };
        if let Some((last_sequence, last)) = previous {
            if identity_from_exchange(last).as_ref() != Some(&identity)
                || !status_after(last).is_some_and(|after| after & 0x200b == before & 0x200b)
            {
                return;
            }
            if last_sequence.checked_add(1) != Some(sequence) {
                // A Case may contain separate completed read sessions on one
                // pooled connection. Consistent inactive status on both sides
                // starts a new span without inferring the missing commands.
                // Global evidence retains its stricter post-read continuity.
                if before & 0x2009 != 0 || saw_read && source != ReplaySource::Case {
                    return;
                }
                read_span = false;
            }
        } else if before & 0x2009 != 0 {
            return;
        }
        if let Some(enabled) = current
            .sql
            .as_deref()
            .and_then(crate::mysql::autocommit::assignment)
        {
            if !successful_control(current)
                || current
                    .response
                    .server_status
                    .is_none_or(|flags| (flags & 2 != 0) != enabled)
                || (before & 0x2009 != 0 && !(enabled && read_span))
            {
                return;
            }
            setups.push(index);
            read_span = false;
        } else if complete_read(current)
            && current.sql.as_deref().is_some_and(|sql| {
                // The parent cache borrows the same dependency file.
                *read_sql.entry(sql).or_insert_with(|| read::classify(sql))
                    == read::Effect::ReadOnly
            })
        {
            if !read_span && before & 0x2009 != 0 {
                return;
            }
            saw_read = true;
            read_span = true;
        } else if successful_prepare(current) {
            // PREPARE executes no SQL; only its later EXECUTE can prove reads.
        } else if successful_ping(current) {
            // Captured PING proves continuity without executing SQL or changing
            // transaction state, including inside an active read transaction.
        } else if successful_end(current, &["commit", "rollback"])
            && (read_span || before & 0x2009 == 0)
        {
            read_span = false;
        } else {
            // Writes, locking reads, explicit BEGIN, failed/unknown exchanges
            // anywhere in this loaded connection keep every setup required.
            return;
        }
        previous = Some((sequence, current));
    }
    if saw_read
        && previous
            .is_some_and(|(_, last)| status_after(last).is_some_and(|flags| flags & 0x2009 == 0))
    {
        optional.extend(
            setups
                .into_iter()
                .map(|index| (index, OptionalSessionExchange::Autocommit)),
        );
    }
}

#[cfg(test)]
mod tests;
