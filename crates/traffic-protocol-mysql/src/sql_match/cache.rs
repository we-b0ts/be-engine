//! Replay-local SQL compilation cache. Only immutable parsing/normalization is
//! cached; identity, policy, runtime parameters and exchange availability are not.
use super::{
    bound_value,
    predicate::{Key, Template},
    query_in,
};
use crate::model::MysqlValue as RecordedMysqlValue;
use crate::sql::{Token, projection::DirectSelect};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, OnceLock},
};

const MAX_ENTRIES: usize = 256;
const MAX_SQL_BYTES: usize = 16 * 1024 * 1024;
const MAX_SINGLE_SQL_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
pub struct SqlCache {
    entries: HashMap<String, Arc<CompiledSql>>,
    order: VecDeque<String>,
    bytes: usize,
    #[cfg(any(test, feature = "test-support"))]
    pub compilations: usize,
}

#[derive(Debug)]
pub struct CompiledSql {
    tokens: Vec<Token>,
    predicate: Option<Template>,
    query_in: Option<query_in::Template>,
    projection: Option<DirectSelect>,
    projection_predicate: Option<Template>,
    param_count: usize,
    constants: OnceLock<Option<Arc<BoundSql>>>,
    in_list_constants: OnceLock<Option<Arc<InListKey>>>,
    metadata: OnceLock<Option<Arc<BoundSql>>>,
}

#[derive(Debug)]
pub struct BoundSql {
    key: SemanticKey,
    pub projection: Option<DirectSelect>,
    projection_key: Option<Key>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InListKey(Key);

#[derive(Debug)]
enum SemanticKey {
    Predicate(Key),
    QueryIn(query_in::Key),
}

impl SqlCache {
    pub fn get(&mut self, sql: &str) -> Arc<CompiledSql> {
        if let Some(compiled) = self.entries.get(sql) {
            return Arc::clone(compiled);
        }
        #[cfg(any(test, feature = "test-support"))]
        {
            self.compilations += 1;
        }
        let compiled = Arc::new(CompiledSql::parse(sql));
        // Account conservatively for the key, tokens, ASTs and lazily bound
        // constant/metadata keys. Large statements still parse without caching.
        let charge = compiled.cache_charge(sql.len());
        if sql.len() > MAX_SINGLE_SQL_BYTES || charge > MAX_SQL_BYTES {
            return compiled;
        }
        while self.entries.len() >= MAX_ENTRIES || self.bytes + charge > MAX_SQL_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.bytes -= self.entries[&oldest].cache_charge(oldest.len());
            self.entries.remove(&oldest);
        }
        self.bytes += charge;
        self.order.push_back(sql.to_owned());
        self.entries.insert(sql.to_owned(), Arc::clone(&compiled));
        compiled
    }
}

impl CompiledSql {
    fn cache_charge(&self, sql_bytes: usize) -> usize {
        sql_bytes.saturating_mul(32)
            + self
                .tokens
                .len()
                .saturating_mul(std::mem::size_of::<Token>() * 32)
    }

    fn parse(sql: &str) -> Self {
        let tokens = crate::sql::bounds::tokens(sql).unwrap_or_default();
        let mut predicate = Template::parse(&tokens, true);
        let query_in = predicate
            .is_none()
            .then(|| query_in::Template::parse(&tokens))
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
            query_in,
            projection,
            projection_predicate,
            constants: OnceLock::new(),
            in_list_constants: OnceLock::new(),
            metadata: OnceLock::new(),
        }
    }

    pub fn bind(
        &self,
        command: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<Arc<BoundSql>> {
        let values = self.parameter_values(command, params)?;
        if self.param_count == 0 {
            self.constants
                .get_or_init(|| self.instantiate(&[]).map(Arc::new))
                .clone()
        } else {
            self.instantiate(&values).map(Arc::new)
        }
    }

    pub fn bind_in_lists(
        &self,
        command: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<Arc<InListKey>> {
        let template = self.predicate.as_ref()?;
        let values = self.parameter_values(command, params)?;
        let bind = || {
            template
                .bind_in_lists(&bind_tokens(&self.tokens, &values)?)
                .map(|key| Arc::new(InListKey(key)))
        };
        if self.param_count == 0 {
            self.in_list_constants.get_or_init(bind).clone()
        } else {
            bind()
        }
    }

    fn parameter_values(
        &self,
        command: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<Vec<Token>> {
        match command {
            "COM_QUERY" if self.param_count == 0 && params.is_none() => Some(Vec::new()),
            "COM_STMT_EXECUTE" => {
                let params = params?;
                (params.len() == self.param_count)
                    .then(|| params.iter().map(bound_value).collect())?
            }
            _ => None,
        }
    }

    pub fn metadata(&self) -> Option<Arc<BoundSql>> {
        self.metadata
            .get_or_init(|| {
                self.instantiate(&vec![Token::Placeholder; self.param_count])
                    .map(Arc::new)
            })
            .clone()
    }

    fn instantiate(&self, params: &[Token]) -> Option<BoundSql> {
        let bound = bind_tokens(&self.tokens, params)?;
        let key = if let Some(template) = &self.predicate {
            SemanticKey::Predicate(template.bind(&bound)?)
        } else {
            SemanticKey::QueryIn(self.query_in.as_ref()?.bind(&bound)?)
        };
        let mut projection = self.projection.clone();
        let projection_key = if let Some(select) = &mut projection {
            select.body = bind_tokens(&select.body, params)?;
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

fn bind_tokens(tokens: &[Token], values: &[Token]) -> Option<Vec<Token>> {
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

impl BoundSql {
    pub fn matches(&self, recorded: &Self, metadata: bool) -> bool {
        match (&self.key, &recorded.key) {
            (SemanticKey::Predicate(actual), SemanticKey::Predicate(recorded)) => {
                actual == recorded || metadata && actual.metadata_matches(recorded)
            }
            (SemanticKey::QueryIn(actual), SemanticKey::QueryIn(recorded)) => {
                actual == recorded || metadata && actual.metadata_matches(recorded)
            }
            _ => false,
        }
    }

    pub fn projection_matches(&self, recorded: &Self, metadata: bool) -> bool {
        self.projection_key
            .as_ref()
            .zip(recorded.projection_key.as_ref())
            .is_some_and(|(a, r)| a == r || metadata && a.metadata_matches(r))
    }
}

#[cfg(test)]
mod tests;
