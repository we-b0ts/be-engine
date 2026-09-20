//! Replay-local SQL compilation cache. Only immutable parsing/normalization is
//! cached; identity, policy, runtime parameters and exchange availability are not.
use super::{
    bound_value, nested_in,
    predicate::{Key, Template},
};
use crate::mysql::sql::{Token, projection::DirectSelect, tokens};
use crate::replay::mysql::RecordedMysqlValue;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, OnceLock},
};

const MAX_ENTRIES: usize = 256;
const MAX_SQL_BYTES: usize = 1024 * 1024;
const MAX_SINGLE_SQL_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
pub(in crate::replay::mysql) struct SqlCache {
    entries: HashMap<String, Arc<CompiledSql>>,
    order: VecDeque<String>,
    bytes: usize,
    #[cfg(test)]
    pub(in crate::replay::mysql) compilations: usize,
}

#[derive(Debug)]
pub(in crate::replay::mysql) struct CompiledSql {
    tokens: Vec<Token>,
    predicate: Option<Template>,
    nested_in: Option<nested_in::Template>,
    projection: Option<DirectSelect>,
    projection_predicate: Option<Template>,
    param_count: usize,
    constants: OnceLock<Option<Arc<BoundSql>>>,
    metadata: OnceLock<Option<Arc<BoundSql>>>,
}

#[derive(Debug)]
pub(in crate::replay::mysql) struct BoundSql {
    key: SemanticKey,
    pub(in crate::replay::mysql) projection: Option<DirectSelect>,
    projection_key: Option<Key>,
}

#[derive(Debug)]
enum SemanticKey {
    Predicate(Key),
    NestedIn(nested_in::Key),
}

impl SqlCache {
    pub(in crate::replay::mysql) fn get(&mut self, sql: &str) -> Arc<CompiledSql> {
        if let Some(compiled) = self.entries.get(sql) {
            return Arc::clone(compiled);
        }
        #[cfg(test)]
        {
            self.compilations += 1;
        }
        let compiled = Arc::new(CompiledSql::parse(sql));
        if sql.len() > MAX_SINGLE_SQL_BYTES {
            return compiled;
        }
        while self.entries.len() >= MAX_ENTRIES || self.bytes + sql.len() > MAX_SQL_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.bytes -= oldest.len();
            self.entries.remove(&oldest);
        }
        self.bytes += sql.len();
        self.order.push_back(sql.to_owned());
        self.entries.insert(sql.to_owned(), Arc::clone(&compiled));
        compiled
    }
}

impl CompiledSql {
    fn parse(sql: &str) -> Self {
        let tokens = (sql.len() <= MAX_SINGLE_SQL_BYTES)
            .then(|| tokens(sql))
            .flatten()
            .filter(|tokens| tokens.len() <= 4096)
            .unwrap_or_default();
        let mut predicate = Template::parse(&tokens, true);
        let nested_in = predicate
            .is_none()
            .then(|| nested_in::Template::parse(&tokens))
            .flatten();
        let projection = predicate
            .as_ref()
            .and_then(|_| DirectSelect::parse(sql, &tokens));
        // Output parameters need result-name/type adaptation. Numeric ORDER
        // BY terms need the existing projection resolver's original spelling:
        // literal 1 is an ordinal, while 1.0 and a bound ? are constants.
        let from = tokens
            .iter()
            .position(|t| t.is("from"))
            .unwrap_or(tokens.len());
        let output_parameter = tokens[..from].contains(&Token::Placeholder);
        let unresolved_sort = projection.is_none()
            && tokens
                .iter()
                .position(|t| t.is("order"))
                .is_some_and(|start| {
                    tokens[start..]
                        .iter()
                        .take_while(|t| !t.is("limit"))
                        .any(|t| matches!(t, Token::Number(_) | Token::Placeholder))
                });
        if output_parameter || unresolved_sort {
            predicate = None;
        }
        let projection_predicate = projection
            .as_ref()
            .and_then(|select| Template::parse(&select.body, false));
        Self {
            param_count: tokens.iter().filter(|t| **t == Token::Placeholder).count(),
            tokens,
            predicate,
            nested_in,
            projection,
            projection_predicate,
            constants: OnceLock::new(),
            metadata: OnceLock::new(),
        }
    }

    pub(in crate::replay::mysql) fn bind(
        &self,
        command: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<Arc<BoundSql>> {
        let values = match command {
            "COM_QUERY" if self.param_count == 0 && params.is_none() => Vec::new(),
            "COM_STMT_EXECUTE" => {
                let params = params?;
                if params.len() != self.param_count {
                    return None;
                }
                params.iter().map(bound_value).collect::<Option<Vec<_>>>()?
            }
            _ => return None,
        };
        if self.param_count == 0 {
            self.constants
                .get_or_init(|| self.instantiate(&[]).map(Arc::new))
                .clone()
        } else {
            self.instantiate(&values).map(Arc::new)
        }
    }

    pub(in crate::replay::mysql) fn metadata(&self) -> Option<Arc<BoundSql>> {
        self.metadata
            .get_or_init(|| {
                self.instantiate(&vec![Token::Placeholder; self.param_count])
                    .map(Arc::new)
            })
            .clone()
    }

    fn instantiate(&self, params: &[Token]) -> Option<BoundSql> {
        fn bind(tokens: &[Token], values: &[Token]) -> Option<Vec<Token>> {
            let mut params = values.iter();
            let bound = tokens
                .iter()
                .map(|t| {
                    if *t == Token::Placeholder {
                        params.next().cloned()
                    } else {
                        Some(t.clone())
                    }
                })
                .collect::<Option<Vec<_>>>()?;
            params.next().is_none().then_some(bound)
        }
        let bound = bind(&self.tokens, params)?;
        let key = if let Some(template) = &self.predicate {
            SemanticKey::Predicate(template.bind(&bound)?)
        } else {
            SemanticKey::NestedIn(self.nested_in.as_ref()?.bind(&bound)?)
        };
        let mut projection = self.projection.clone();
        let projection_key = if let Some(select) = &mut projection {
            select.body = bind(&select.body, params)?;
            self.projection_predicate
                .as_ref()
                .and_then(|template| template.bind(&select.body))
        } else {
            None
        };
        Some(BoundSql {
            key,
            projection,
            projection_key,
        })
    }
}

impl BoundSql {
    pub(in crate::replay::mysql) fn matches(&self, recorded: &Self, metadata: bool) -> bool {
        match (&self.key, &recorded.key) {
            (SemanticKey::Predicate(actual), SemanticKey::Predicate(recorded)) => {
                actual == recorded || metadata && actual.metadata_matches(recorded)
            }
            (SemanticKey::NestedIn(actual), SemanticKey::NestedIn(recorded)) => {
                actual == recorded || metadata && actual.metadata_matches(recorded)
            }
            _ => false,
        }
    }

    pub(in crate::replay::mysql) fn projection_matches(
        &self,
        recorded: &Self,
        metadata: bool,
    ) -> bool {
        self.projection_key
            .as_ref()
            .zip(recorded.projection_key.as_ref())
            .is_some_and(|(a, r)| a == r || metadata && a.metadata_matches(r))
    }
}

#[cfg(test)]
mod tests;
