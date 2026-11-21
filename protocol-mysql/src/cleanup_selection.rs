//! Scoped transaction ends and wire predecessors; live state decides precedence.
use crate::{
    session_constraints::SessionContext,
    session_identity::{SessionIdentity as ReplaySessionIdentity, normalize_identity_value},
    values::normalize_sql,
};
use std::{collections::HashMap, sync::Arc};
use traffic_model::attribution::DependencyScope as ReplaySource;
use traffic_protocol::connection::Endpoint as TargetKey;
use uuid::Uuid;

pub trait SessionInventory: SessionContext {
    fn exchange_count(&self) -> usize;
}

type ScopeKey = (Option<String>, TargetKey, Option<String>, Option<String>);

#[derive(Debug, Default)]
pub struct Index {
    count: usize,
    scopes: HashMap<ScopeKey, Scope>,
}

#[derive(Debug, Default)]
struct Scope {
    ends: [Vec<usize>; 2],
    end_candidates: [std::sync::OnceLock<Arc<[usize]>>; 2],
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
    if !matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE") {
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
    pub fn register(&mut self, exchanges: &impl SessionInventory) {
        if self.count > exchanges.exchange_count() {
            *self = Self::default();
        }
        for index in self.count..exchanges.exchange_count() {
            let exchange = exchanges.exchange(index);
            if exchange.source != ReplaySource::Case {
                continue;
            }
            let key = (
                exchange.case_id.map(str::to_owned),
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
            if matches!(
                exchange.record.command.as_str(),
                "COM_QUERY" | "COM_STMT_EXECUTE"
            ) && let Some(sql) = exchange.record.sql.as_deref()
                && let Some(kind) = end_kind(&exchange.record.command, Some(&normalize_sql(sql)))
            {
                scope.ends[kind].push(index);
                scope.end_candidates[kind].take();
            }
        }
        self.count = exchanges.exchange_count();
    }

    pub fn candidates(
        &mut self,
        exchanges: &impl SessionInventory,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        normalized_sql: Option<&str>,
    ) -> Option<Arc<[usize]>> {
        let kind = end_kind(command, normalized_sql)?;
        let scope = scope_key(case, identity)?;
        self.register(exchanges);
        Some(self.scopes.get(&scope).map_or_else(
            || Arc::from([]),
            |scope| {
                Arc::clone(
                    scope.end_candidates[kind]
                        .get_or_init(|| Arc::from(scope.ends[kind].as_slice())),
                )
            },
        ))
    }

    pub fn preferred_end(
        &mut self,
        exchanges: &impl SessionInventory,
        active_case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: &str,
        normalized_sql: Option<&str>,
    ) -> Option<usize> {
        if command != "COM_QUERY" {
            return None;
        }
        let kind = end_kind(command, normalized_sql)?;
        self.register(exchanges);
        let scope = self.scopes.get(&scope_key(active_case, identity)?)?;
        let ends = &scope.ends[kind];
        if !ends.iter().any(|index| {
            let exchange = exchanges.exchange(*index);
            exchange.record.command == "COM_QUERY"
                && exchange.optional_session.is_some()
                && exchanges.available(*index)
        }) {
            return None;
        }
        ends.iter().copied().find(|index| {
            let exchange = exchanges.exchange(*index);
            if exchange.record.command != "COM_QUERY"
                || exchange.optional_session.is_some()
                || !exchanges.available(*index)
            {
                return false;
            }
            let record = exchange.record;
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
                    .find(|index| exchanges.delivered(**index))
                    .map(|index| exchanges.exchange(*index))
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
