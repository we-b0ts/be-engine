//! An optional foreign close must not steal a current business transaction's end.
use super::*;

pub(super) fn preferred_end(
    exchanges: &[ReplayExchange],
    active_case: Option<&str>,
    identity: &ReplaySessionIdentity,
    command: &str,
    normalized_sql: Option<&str>,
) -> Option<usize> {
    let sql = normalized_sql?;
    if command != "COM_QUERY" || !matches!(sql, "commit" | "rollback") {
        return None;
    }
    let in_scope = |exchange: &ReplayExchange| {
        exchange.source == ReplaySource::Case
            && active_case_matches(active_case, exchange)
            && identity_matches_exchange(identity, &exchange.identity)
    };
    let matches_end = |exchange: &ReplayExchange| {
        exchange.status.is_available()
            && exchange.record.command == command
            && exchange
                .record
                .sql
                .as_deref()
                .is_some_and(|s| normalize_sql(s) == sql)
            && in_scope(exchange)
    };
    if !exchanges
        .iter()
        .any(|exchange| exchange.optional_session.is_some() && matches_end(exchange))
    {
        return None;
    }
    let completed: HashMap<_, _> = exchanges
        .iter()
        .filter(|exchange| exchange.status.is_consumed() && in_scope(exchange))
        .filter_map(|exchange| {
            Some((
                (
                    exchange.record.connection_id?,
                    exchange.record.query_sequence?,
                ),
                exchange,
            ))
        })
        .collect();
    exchanges.iter().enumerate().find_map(|(index, exchange)| {
        if exchange.optional_session.is_some() || !matches_end(exchange) {
            return None;
        }
        let record = &exchange.record;
        let before = record.server_status_before?;
        if before & 0x2009 != 1 {
            return None;
        }
        let previous = completed.get(&(
            record.connection_id?,
            record.query_sequence?.checked_sub(1)?,
        ))?;
        (previous.identity == exchange.identity
            && previous
                .record
                .response
                .server_status
                .is_some_and(|after| after & 0x200b == before & 0x200b))
        .then_some(index)
    })
}
