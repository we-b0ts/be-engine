//! A framework may set READ COMMITTED once when opening a physical connection.
use super::*;
use crate::{
    autocommit,
    isolation::{Level, Scope, setting},
};

pub fn classify<'a, E: 'a>(
    records: impl Iterator<Item = (usize, &'a RecordedMysqlExchange<E>)>,
) -> BTreeMap<usize, OptionalSessionExchange> {
    // Only inspect a bounded prefix of the original wire sequence. A Case
    // whose connection began in a different scope cannot supply this proof.
    const MAX_PREFIX: u64 = 16;
    let mut connections = HashMap::<Uuid, BTreeMap<u64, (usize, &RecordedMysqlExchange<E>)>>::new();
    let mut ambiguous = BTreeSet::new();
    for (index, exchange) in records {
        let Some(connection) = exchange.connection_id else {
            continue;
        };
        let Some(sequence) = exchange.query_sequence else {
            ambiguous.insert(connection);
            continue;
        };
        if sequence <= MAX_PREFIX
            && connections
                .entry(connection)
                .or_default()
                .insert(sequence, (index, exchange))
                .is_some()
        {
            ambiguous.insert(connection);
        }
    }
    connections
        .into_iter()
        .filter(|(connection, _)| !ambiguous.contains(connection))
        .filter_map(|(_, exchanges)| {
            let index = read_committed_default(&exchanges)?;
            Some((index, OptionalSessionExchange::ConnectionReadCommitted))
        })
        .collect()
}

fn read_committed_default<E>(
    exchanges: &BTreeMap<u64, (usize, &RecordedMysqlExchange<E>)>,
) -> Option<usize> {
    let (_, first) = exchanges.get(&1)?;
    if !is_nonsemantic_session_setup(first) {
        return None;
    }
    let identity = identity_from_exchange(first)?;
    let mut previous = first.response.server_status? & 0x200b;
    let mut autocommit_disabled = false;
    for (expected, (&sequence, &(index, exchange))) in (2..).zip(exchanges.range(2..)) {
        let before = exchange.server_status_before? & 0x200b;
        let after = exchange.response.server_status? & 0x200b;
        if expected != sequence
            || before != previous
            || before & 0x2009 != 0
            || after & 0x2009 != 0
            || exchange.lifecycle_cleanup
            || identity_from_exchange(exchange).as_ref() != Some(&identity)
        {
            return None;
        }
        previous = after;
        if is_nonsemantic_session_setup(exchange) {
            continue;
        }
        let sql = exchange.sql.as_deref()?;
        if before == 2
            && after == 0
            && autocommit::assignment(sql) == Some(false)
            && successful_control(exchange)
        {
            autocommit_disabled = true;
            continue;
        }
        let (_, commit) = exchanges.get(&(sequence + 1))?;
        // The initialization hook closes its SET with an empty COMMIT. It
        // cannot have executed any business operation before this point.
        return (autocommit_disabled
            && before == 0
            && after == 0
            && setting(sql) == Some((Scope::Session, Level::ReadCommitted))
            && successful_control(exchange)
            && identity_from_exchange(commit).as_ref() == Some(&identity)
            && !commit.lifecycle_cleanup
            && commit
                .server_status_before
                .is_some_and(|flags| flags & 0x200b == 0)
            && successful_end(commit, &["commit"]))
        .then_some(index);
    }
    None
}
