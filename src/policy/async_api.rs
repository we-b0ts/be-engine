//! Recording lifecycle declarations; completion never relaxes replay values.
use super::{Endpoint, MysqlPolicy, RedisPolicy};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const ASYNC_API_ID: &str = "capture.async_api";
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncApiRule {
    #[serde(default, deserialize_with = "super::strict_map::unique_map")]
    pub when: BTreeMap<String, Value>,
    pub end: Vec<AsyncEnd>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AsyncEndDocument", into = "AsyncEndDocument")]
pub enum AsyncEnd {
    Mysql(AsyncMysqlEnd),
    Redis(AsyncRedisEnd),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AsyncEndDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mysql: Option<AsyncMysqlEnd>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redis: Option<AsyncRedisEnd>,
}

impl TryFrom<AsyncEndDocument> for AsyncEnd {
    type Error = &'static str;

    fn try_from(document: AsyncEndDocument) -> std::result::Result<Self, Self::Error> {
        match (document.mysql, document.redis) {
            (Some(end), None) => Ok(Self::Mysql(end)),
            (None, Some(end)) => Ok(Self::Redis(end)),
            _ => Err("async terminal resource requires exactly one mysql or redis declaration"),
        }
    }
}

impl From<AsyncEnd> for AsyncEndDocument {
    fn from(end: AsyncEnd) -> Self {
        match end {
            AsyncEnd::Mysql(mysql) => Self {
                mysql: Some(mysql),
                redis: None,
            },
            AsyncEnd::Redis(redis) => Self {
                mysql: None,
                redis: Some(redis),
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncMysqlEnd {
    pub sql: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncRedisEnd {
    pub operation: String,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub occurrence: usize,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
}

fn one() -> usize {
    1
}
fn is_one(value: &usize) -> bool {
    *value == 1
}

pub fn compile_async_api(
    rules: &BTreeMap<String, AsyncApiRule>,
    mysql: Option<&MysqlPolicy>,
    redis: Option<&RedisPolicy>,
) -> Result<BTreeMap<String, AsyncApiRule>> {
    ensure!(rules.len() <= 256, "async_api exceeds 256 API selectors");
    let mut normalized = rules.clone();
    for (api, rule) in &mut normalized {
        super::compiler::validate_api(api)?;
        ensure!(
            !api.starts_with("MOTAN "),
            "async_api lifecycle requires an HTTP API"
        );
        ensure!(
            rule.when.len() <= 32,
            "async API condition exceeds 32 fields"
        );
        for (pointer, value) in &rule.when {
            super::validate_pointer(pointer, true)?;
            ensure!(
                !pointer.split('/').any(|part| part == "*")
                    && !value.is_array()
                    && !value.is_object()
                    && value.to_string().len() <= 4096,
                "async API conditions require bounded literal JSON scalar pointers"
            );
        }
        ensure!(
            (1..=32).contains(&rule.end.len()),
            "async API requires 1..32 terminal resources"
        );
        for resource in &mut rule.end {
            match resource {
                AsyncEnd::Mysql(end) => {
                    ensure!(
                        !end.sql.trim().is_empty() && end.sql.len() <= 8192,
                        "async MySQL SQL must be nonempty and at most 8192 bytes"
                    );
                    let tokens = crate::mysql::sql::bounds::statement(&end.sql)
                        .context("async MySQL completion requires one SQL statement")?;
                    ensure!(
                        !tokens.is_empty()
                            && !matches!(
                                tokens.first(),
                                Some(crate::mysql::sql::Token::Placeholder)
                            ),
                        "async MySQL completion requires concrete SQL tokens"
                    );
                    for (index, _) in tokens
                        .iter()
                        .enumerate()
                        .filter(|(_, token)| matches!(token, crate::mysql::sql::Token::Placeholder))
                    {
                        ensure!(
                            index > 0
                                && !["from", "into", "update", "join", "table", "as", "."]
                                    .iter()
                                    .any(|word| tokens[index - 1].is(word)),
                            "SQL ? matches one scalar value, never a physical identifier"
                        );
                    }
                    if end.database.is_none() {
                        end.database = mysql.and_then(|mysql| mysql.database.clone());
                    }
                    if let Some(database) = &end.database {
                        ensure!(
                            !database.is_empty()
                                && database.len() <= 256
                                && !database.chars().any(char::is_control),
                            "async MySQL database requires a bounded physical name"
                        );
                    }
                    if let Some(endpoint) = &end.endpoint {
                        endpoint.validate()?;
                    }
                }
                AsyncEnd::Redis(end) => {
                    ensure!(
                        !end.operation.is_empty()
                            && end.operation.len() <= 64
                            && end
                                .operation
                                .bytes()
                                .all(|byte| byte.is_ascii_alphabetic() || byte == b'_'),
                        "async Redis operation requires a concrete command"
                    );
                    end.operation.make_ascii_uppercase();
                    ensure!(
                        (1..=1024).contains(&end.occurrence),
                        "async Redis terminal occurrence requires 1..1024"
                    );
                    ensure!(
                        !end.key.is_empty()
                            && end.key.len() <= 1024
                            && end.key.bytes().filter(|byte| *byte == b'*').count() <= 1,
                        "async Redis key requires a bounded physical key or one wildcard"
                    );
                    if end.database.is_none() {
                        end.database = redis.and_then(|redis| redis.database);
                    }
                    ensure!(
                        end.database.is_none_or(|database| database >= 0),
                        "async Redis database must be nonnegative"
                    );
                    if let Some(endpoint) = &end.endpoint {
                        endpoint.validate()?;
                    }
                }
            }
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests;

pub fn async_api_matches(
    api: &str,
    rule: &AsyncApiRule,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> bool {
    let (Ok(api), Ok(method), Ok(uri)) = (
        api.parse::<crate::RecordingApi>(),
        method.parse::<hyper::Method>(),
        uri.parse::<hyper::Uri>(),
    ) else {
        return false;
    };
    api.matches(&method, &uri)
        && rule
            .when
            .iter()
            .all(|(pointer, value)| body.and_then(|body| body.pointer(pointer)) == Some(value))
}
