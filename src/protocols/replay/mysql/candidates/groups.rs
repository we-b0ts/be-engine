//! Exact Source SELECT groups share comparison work, not response or claim state.
use super::*;
use std::collections::HashMap;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_SQL_BYTES: usize = 16 * 1024;

#[derive(Debug, Default)]
pub(super) struct Groups {
    by_sql: HashMap<String, usize>,
    members: Vec<Option<usize>>,
    bytes: usize,
}

impl Groups {
    pub(super) fn register(&mut self, exchange: &ReplayExchange, proven_select: bool) {
        let id = (proven_select
            && exchange.source == ReplaySource::Case
            && exchange.record.command == "COM_QUERY"
            && exchange.record.params.is_none())
        .then_some(exchange.record.sql.as_deref())
        .flatten()
        .filter(|sql| sql.len() <= MAX_SQL_BYTES)
        .and_then(|sql| {
            if let Some(&id) = self.by_sql.get(sql) {
                return Some(id);
            }
            if self.bytes + sql.len() > MAX_BYTES {
                return None;
            }
            let id = self.by_sql.len();
            self.by_sql.insert(sql.to_owned(), id);
            self.bytes += sql.len();
            Some(id)
        });
        self.members.push(id);
    }

    pub(super) fn get(&self, index: usize) -> Option<usize> {
        self.members.get(index).copied().flatten()
    }
}
