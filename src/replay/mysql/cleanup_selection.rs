//! Scoped transaction ends and wire predecessors; live state decides precedence.
use super::*;

type ScopeKey = (Option<String>, TargetKey, Option<String>, Option<String>);

#[derive(Debug, Default)]
pub(super) struct Index {
    count: usize,
    scopes: HashMap<ScopeKey, Scope>,
}

#[derive(Debug, Default)]
struct Scope {
    ends: [Vec<usize>; 2],
    wires: HashMap<(Uuid, u64), Vec<usize>>,
}

fn scope_key(case: Option<&str>, identity: &ReplaySessionIdentity) -> Option<ScopeKey> {
    Some((
        case.map(str::to_owned),
        identity.target.clone()?,
        normalize_identity_value(identity.database.as_deref()),
        normalize_identity_value(identity.username.as_deref()),
    ))
}

fn end_kind(command: &str, normalized_sql: Option<&str>) -> Option<usize> {
    if command != "COM_QUERY" {
        return None;
    }
    match normalized_sql? {
        "commit" => Some(0),
        "rollback" => Some(1),
        _ => None,
    }
}

impl Index {
    /// Register appended immutable inventory, including test/repair constructors.
    /// Status and optional classifications are deliberately not cached.
    pub(super) fn register(&mut self, exchanges: &[ReplayExchange]) {
        if self.count > exchanges.len() {
            *self = Self::default();
        }
        for (index, exchange) in exchanges.iter().enumerate().skip(self.count) {
            if exchange.source != ReplaySource::Case {
                continue;
            }
            let key = (
                exchange.case_id.clone(),
                exchange.identity.target.clone(),
                normalize_identity_value(exchange.identity.database.as_deref()),
                normalize_identity_value(exchange.identity.username.as_deref()),
            );
            let scope = self.scopes.entry(key).or_default();
            if let Some(wire) = exchange
                .record
                .connection_id
                .zip(exchange.record.query_sequence)
            {
                scope.wires.entry(wire).or_default().push(index);
            }
            if exchange.record.command == "COM_QUERY"
                && let Some(sql) = exchange.record.sql.as_deref()
                && let Some(kind) = end_kind("COM_QUERY", Some(&normalize_sql(sql)))
            {
                scope.ends[kind].push(index);
            }
        }
        self.count = exchanges.len();
    }

    pub(super) fn preferred_end(
        &mut self,
        exchanges: &[ReplayExchange],
        active_case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        normalized_sql: Option<&str>,
    ) -> Option<usize> {
        let kind = end_kind(command, normalized_sql)?;
        self.register(exchanges);
        let scope = self.scopes.get(&scope_key(active_case, identity)?)?;
        let ends = &scope.ends[kind];
        if !ends.iter().any(|index| {
            let exchange = &exchanges[*index];
            exchange.optional_session.is_some() && exchange.status.is_available()
        }) {
            return None;
        }
        ends.iter().copied().find(|index| {
            let exchange = &exchanges[*index];
            if exchange.optional_session.is_some() || !exchange.status.is_available() {
                return false;
            }
            let record = &exchange.record;
            let Some(before) = record
                .server_status_before
                .filter(|flags| flags & 0x2009 == 1)
            else {
                return false;
            };
            let Some(wire) = record.connection_id.zip(
                record
                    .query_sequence
                    .and_then(|sequence| sequence.checked_sub(1)),
            ) else {
                return false;
            };
            // Preserve the last-consumed duplicate precedence of the original
            // completed-record map, including the exact raw identity check.
            let previous = scope.wires.get(&wire).and_then(|indices| {
                indices
                    .iter()
                    .rev()
                    .map(|index| &exchanges[*index])
                    .find(|previous| previous.status.is_consumed())
            });
            previous.is_some_and(|previous| {
                previous.identity == exchange.identity
                    && previous
                        .record
                        .response
                        .server_status
                        .is_some_and(|after| after & 0x200b == before & 0x200b)
            })
        })
    }
}

#[cfg(test)]
mod tests;
