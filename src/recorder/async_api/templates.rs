//! Immutable end templates prepared once for each Case's scenario matcher.
use std::sync::Arc;

use crate::mysql::sql::{self, Token};
use crate::policy::{AsyncApiRule, AsyncEnd};
use crate::recorder::MysqlValue;

#[derive(Debug, Clone)]
pub(super) struct Templates(Arc<[EndTemplate]>);

#[derive(Debug)]
enum EndTemplate {
    Key(KeyMatcher),
    Sql(Option<Box<[Token]>>),
    Other,
}

#[derive(Debug)]
enum KeyMatcher {
    Exact(Box<[u8]>),
    Wildcard {
        prefix: Box<[u8]>,
        suffix: Box<[u8]>,
    },
}

impl KeyMatcher {
    fn new(pattern: &str) -> Self {
        match pattern.split_once('*') {
            Some((prefix, suffix)) => Self::Wildcard {
                prefix: prefix.as_bytes().into(),
                suffix: suffix.as_bytes().into(),
            },
            None => Self::Exact(pattern.as_bytes().into()),
        }
    }

    fn matches(&self, key: &[u8]) -> bool {
        match self {
            Self::Exact(expected) => expected.as_ref() == key,
            Self::Wildcard { prefix, suffix } => {
                key.len() >= prefix.len() + suffix.len()
                    && key.starts_with(prefix)
                    && key.ends_with(suffix)
            }
        }
    }
}

impl Templates {
    pub(super) fn new(rule: &AsyncApiRule) -> Self {
        Self(
            rule.end
                .iter()
                .map(|end| match end {
                    AsyncEnd::Redis(end) => EndTemplate::Key(KeyMatcher::new(&end.key)),
                    AsyncEnd::Mysql(end) => EndTemplate::Sql(
                        sql::bounds::statement(&end.sql).map(Vec::into_boxed_slice),
                    ),
                    AsyncEnd::RedisPublish(_) | AsyncEnd::Http(_) => EndTemplate::Other,
                })
                .collect::<Vec<_>>()
                .into(),
        )
    }

    pub(super) fn key_matches(&self, index: usize, key: &[u8]) -> bool {
        matches!(self.0.get(index), Some(EndTemplate::Key(matcher)) if matcher.matches(key))
    }

    pub(super) fn sql_matches(&self, index: usize, actual: &[Token]) -> bool {
        let Some(EndTemplate::Sql(Some(pattern))) = self.0.get(index) else {
            return false;
        };
        pattern.len() == actual.len()
            && pattern.iter().zip(actual).all(|(expected, actual)| {
                expected == actual || *expected == Token::Placeholder && actual.is_value()
            })
    }
}

/// Prepare the observed SQL once, then reuse it across every applicable end.
pub(super) fn actual_sql(actual: &str, parameters: &[MysqlValue]) -> Option<Vec<Token>> {
    let mut actual = sql::bounds::statement(actual)?;
    let mut parameters = parameters.iter();
    for token in &mut actual {
        if *token == Token::Placeholder {
            *token = parameters.next().and_then(bound_value)?;
        }
    }
    parameters.next().is_none().then_some(actual)
}

fn bound_value(value: &MysqlValue) -> Option<Token> {
    match value.kind.as_str() {
        "null" => Some(Token::Null),
        "integer" | "float" | "decimal" => {
            let value = value.value.as_ref()?;
            let text = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            sql::number(&text).map(Token::Number)
        }
        "boolean" | "bool" => value
            .value
            .as_ref()?
            .as_bool()
            .map(|value| Token::Number(u8::from(value).to_string())),
        "string" | "bytes" | "binary" | "date" | "datetime" | "time" | "json" => {
            let bytes = if let Some(raw) = &value.raw {
                super::decode(raw)?
            } else {
                value.value.as_ref()?.as_str()?.as_bytes().to_vec()
            };
            Some(Token::Bytes(bytes))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
