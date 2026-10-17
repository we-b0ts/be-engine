//! Ordered immutable scope indexes. Availability and all policy decisions stay live.
use super::*;
use std::{collections::HashMap, sync::Arc};

type Key = (
    u8,
    Option<String>,
    String,
    u16,
    Option<String>,
    Option<String>,
);

#[derive(Debug, Default)]
pub(super) struct Candidates {
    count: usize,
    scopes: HashMap<Key, Vec<usize>>,
}

fn key(source: ReplaySource, case: Option<&str>, identity: &ReplaySessionIdentity) -> Option<Key> {
    let target = identity.target.as_ref()?;
    Some((
        u8::from(source == ReplaySource::Global),
        if source == ReplaySource::Case {
            case.map(str::to_owned)
        } else {
            None
        },
        target.host.clone(),
        target.port,
        normalize_identity_value(identity.database.as_deref()),
        normalize_identity_value(identity.username.as_deref()),
    ))
}

impl Candidates {
    pub(super) fn select(
        &mut self,
        exchanges: &[ReplayExchange],
        source: ReplaySource,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        command: Option<&str>,
    ) -> Arc<[usize]> {
        // Some test/repair constructors append directly. Reconcile their immutable
        // inventory before lookup; payload release never changes vector positions.
        if self.count > exchanges.len() {
            *self = Self::default();
        }
        for (index, exchange) in exchanges.iter().enumerate().skip(self.count) {
            let identity = ReplaySessionIdentity {
                target: Some(exchange.identity.target.clone()),
                database: exchange.identity.database.clone(),
                username: exchange.identity.username.clone(),
            };
            if let Some(key) = key(exchange.source, exchange.case_id.as_deref(), &identity) {
                self.scopes.entry(key).or_default().push(index);
            }
        }
        self.count = exchanges.len();
        let Some(key) = key(source, case, identity) else {
            return Arc::from([]);
        };
        self.scopes
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|index| {
                command.is_none_or(|command| {
                    let recorded = exchanges[*index].record.command.as_str();
                    command == recorded
                        || [command, recorded]
                            .into_iter()
                            .all(|c| matches!(c, "COM_QUERY" | "COM_STMT_EXECUTE"))
                })
            })
            .collect::<Vec<_>>()
            .into()
    }
}
