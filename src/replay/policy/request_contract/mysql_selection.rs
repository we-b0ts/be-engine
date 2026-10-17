//! Policy-local SQL templates and bounded immutable statement parsing.
//! Bound parameters and case applicability are evaluated on every call.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::{CompiledPolicy, NativeEffect, Protocol};
use crate::replay::RecordedMysqlExchange;
use crate::replay::policy::sql_template::{SqlValueTemplate, bounded_statement_tokens};
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_ENTRIES: usize = 256;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_STATEMENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default)]
pub(super) struct MysqlSelection {
    templates: BTreeMap<String, SqlValueTemplate>,
    statements: Mutex<Statements>,
    #[cfg(test)]
    parses: AtomicUsize,
}

#[derive(Debug, Default)]
struct Statements {
    entries: HashMap<Arc<str>, Statement>,
    order: VecDeque<Arc<str>>,
    bytes: usize,
}

#[derive(Debug)]
struct Statement {
    tokens: Option<Arc<Vec<Token>>>,
    bytes: usize,
}

impl MysqlSelection {
    pub(super) fn new(compiled: Option<&CompiledPolicy>) -> Result<Self> {
        let mut selection = Self::default();
        if let Some(compiled) = compiled {
            for compiled in &compiled.rules {
                let rule = &compiled.rule;
                if rule
                    .selector
                    .resource
                    .as_ref()
                    .is_some_and(|r| r.protocol == Protocol::Mysql)
                    && let Some(sql) = &rule.selector.sql
                {
                    selection
                        .templates
                        .insert(rule.id.clone(), SqlValueTemplate::new(sql, &[], &[], None)?);
                }
            }
            for compiled in &compiled.native {
                let rule = &compiled.rule;
                if matches!(rule.effect, NativeEffect::MysqlValues(_))
                    && let Some(sql) = &rule.selector.sql
                {
                    selection.templates.insert(
                        rule.id.clone(),
                        SqlValueTemplate::new(
                            sql,
                            &rule.selector.tables,
                            &rule.selector.table_patterns,
                            rule.selector.table_series.as_ref(),
                        )?,
                    );
                }
            }
        }
        Ok(selection)
    }

    pub(super) fn matches(
        &self,
        id: &str,
        record: &RecordedMysqlExchange,
        statement: &mut Option<Option<Arc<Vec<Token>>>>,
    ) -> bool {
        let (Some(template), Some(sql)) = (self.templates.get(id), record.sql.as_deref()) else {
            return false;
        };
        if !template.could_match(sql) {
            return false;
        }
        statement
            .get_or_insert_with(|| {
                let tokens = self.statement_tokens(sql)?;
                let params = record.params.as_deref().unwrap_or_default();
                if params.is_empty() && !tokens.contains(&Token::Placeholder) {
                    Some(tokens)
                } else {
                    crate::replay::mysql::sql_match::materialize_tokens((*tokens).clone(), params)
                        .map(Arc::new)
                }
            })
            .as_ref()
            .is_some_and(|tokens| template.matches_tokens(tokens))
    }

    fn statement_tokens(&self, sql: &str) -> Option<Arc<Vec<Token>>> {
        if sql.len() > MAX_STATEMENT_BYTES {
            return None;
        }
        if let Some(tokens) = self
            .statements
            .lock()
            .expect("SQL statement cache")
            .get(sql)
        {
            return tokens;
        }
        // Never hold the shared cache lock while parsing large literals or
        // calculating their retained size. Only immutable raw tokens are cached.
        #[cfg(test)]
        self.parses.fetch_add(1, Ordering::Relaxed);
        let tokens = bounded_statement_tokens(sql).map(Arc::new);
        let bytes = statement_bytes(sql, tokens.as_deref());
        if bytes > MAX_BYTES {
            return tokens;
        }
        let key = Arc::<str>::from(sql);
        let (tokens, retired) = self
            .statements
            .lock()
            .expect("SQL statement cache")
            .insert(key, tokens, bytes);
        // A bounded eviction can release many token strings. Drop them after
        // releasing the cache lock, including when another parser won the race.
        drop(retired);
        tokens
    }
}

impl Statements {
    fn get(&self, sql: &str) -> Option<Option<Arc<Vec<Token>>>> {
        self.entries.get(sql).map(|entry| entry.tokens.clone())
    }

    fn insert(
        &mut self,
        sql: Arc<str>,
        tokens: Option<Arc<Vec<Token>>>,
        bytes: usize,
    ) -> (Option<Arc<Vec<Token>>>, Vec<(Arc<str>, Statement)>) {
        if let Some(previous) = self.entries.get(sql.as_ref()) {
            return (
                previous.tokens.clone(),
                vec![(sql, Statement { tokens, bytes })],
            );
        }
        let mut retired = Vec::new();
        while self.entries.len() >= MAX_ENTRIES || self.bytes + bytes > MAX_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some((key, entry)) = self.entries.remove_entry(oldest.as_ref()) {
                self.bytes -= entry.bytes;
                retired.push((key, entry));
            }
        }
        self.entries.insert(
            Arc::clone(&sql),
            Statement {
                tokens: tokens.clone(),
                bytes,
            },
        );
        self.order.push_back(sql);
        self.bytes += bytes;
        (tokens, retired)
    }
}

fn statement_bytes(sql: &str, tokens: Option<&Vec<Token>>) -> usize {
    sql.len()
        + tokens.map_or(0, |tokens| {
            tokens.capacity() * std::mem::size_of::<Token>()
                + tokens
                    .iter()
                    .map(|token| match token {
                        Token::Word(s)
                        | Token::Identifier(s)
                        | Token::Number(s)
                        | Token::Symbol(s) => s.capacity(),
                        Token::Bytes(bytes) => bytes.capacity(),
                        _ => 0,
                    })
                    .sum::<usize>()
        })
}

#[cfg(test)]
mod tests;
