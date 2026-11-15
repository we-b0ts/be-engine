//! Reuse a bound Target IN-list proof across candidates in the first pass.
use super::*;
use sql_match::cache::{InListKey, SqlCache};
use std::{collections::HashMap, sync::Arc};

#[derive(Default)]
pub(super) struct Comparison {
    actual: Option<Option<Arc<InListKey>>>,
    groups: HashMap<usize, bool>,
}

impl Comparison {
    pub(super) fn matches(
        &mut self,
        cache: &mut SqlCache,
        record: &RecordedMysqlExchange,
        actual: (&str, &str, Option<&[RecordedMysqlValue]>),
        group: Option<usize>,
    ) -> bool {
        let (command, sql, params) = actual;
        let Some(actual) = self
            .actual
            .get_or_insert_with(|| cache.get(sql).bind_in_lists(command, params))
            .as_ref()
        else {
            return false;
        };
        let mut compare = || {
            record
                .sql
                .as_deref()
                .and_then(|sql| {
                    cache
                        .get(sql)
                        .bind_in_lists(&record.command, record.params.as_deref())
                })
                .is_some_and(|recorded| recorded == *actual)
        };
        let equal = match group {
            Some(group) => *self.groups.entry(group).or_insert_with(compare),
            None => compare(),
        };
        equal && projection::complete_resultset(record)
    }
}
