//! Recording lifecycle declarations; completion never relaxes replay values.
use super::Endpoint;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub mod redis_publish;
pub mod redis_response;
pub use redis_publish::AsyncRedisPublishEnd;
pub use redis_response::AsyncRedisResponse;

pub const ASYNC_API_ID: &str = "capture.async_api";
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncApiRule {
    #[serde(default, deserialize_with = "super::strict_map::unique_map")]
    pub when: BTreeMap<String, Value>,
    #[serde(
        default,
        deserialize_with = "super::strict_map::unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub when_response: BTreeMap<String, Value>,
    #[serde(
        default,
        deserialize_with = "super::strict_map::unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub unless_response: BTreeMap<String, Value>,
    pub end: Vec<AsyncEnd>,
}

/// Ordered scenarios. A single legacy declaration remains valid input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AsyncApiRules(pub Vec<AsyncApiRule>);

impl<'de> Deserialize<'de> for AsyncApiRules {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Declaration {
            Single(AsyncApiRule),
            Multiple(Vec<AsyncApiRule>),
        }
        Ok(Self(match Declaration::deserialize(deserializer)? {
            Declaration::Single(rule) => vec![rule],
            Declaration::Multiple(rules) => rules,
        }))
    }
}

impl std::ops::Deref for AsyncApiRules {
    type Target = [AsyncApiRule];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AsyncEndDocument", into = "AsyncEndDocument")]
pub enum AsyncEnd {
    Mysql(AsyncMysqlEnd),
    Redis(AsyncRedisEnd),
    RedisPublish(AsyncRedisPublishEnd),
    Http(AsyncHttpEnd),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncEndDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql: Option<AsyncMysqlEnd>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisEndDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<AsyncHttpEnd>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum RedisEndDocument {
    Key(AsyncRedisEnd),
    Publish(AsyncRedisPublishEnd),
}

impl TryFrom<AsyncEndDocument> for AsyncEnd {
    type Error = &'static str;

    fn try_from(document: AsyncEndDocument) -> std::result::Result<Self, Self::Error> {
        match (document.mysql, document.redis, document.http) {
            (Some(end), None, None) => Ok(Self::Mysql(end)),
            (None, Some(RedisEndDocument::Key(end)), None) => Ok(Self::Redis(end)),
            (None, Some(RedisEndDocument::Publish(end)), None) => Ok(Self::RedisPublish(end)),
            (None, None, Some(end)) => Ok(Self::Http(end)),
            _ => {
                Err("async terminal resource requires exactly one mysql, redis or http declaration")
            }
        }
    }
}

impl From<AsyncEnd> for AsyncEndDocument {
    fn from(end: AsyncEnd) -> Self {
        match end {
            AsyncEnd::Mysql(mysql) => Self {
                mysql: Some(mysql),
                redis: None,
                http: None,
            },
            AsyncEnd::Redis(redis) => Self {
                mysql: None,
                redis: Some(RedisEndDocument::Key(redis)),
                http: None,
            },
            AsyncEnd::RedisPublish(redis) => Self {
                mysql: None,
                redis: Some(RedisEndDocument::Publish(redis)),
                http: None,
            },
            AsyncEnd::Http(http) => Self {
                mysql: None,
                redis: None,
                http: Some(http),
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
    #[serde(default, skip_serializing_if = "AsyncRedisResponse::is_any")]
    pub when_response: AsyncRedisResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
}

/// A complete successful dependency exchange, never merely a connection/send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncHttpEnd {
    pub method: String,
    pub endpoint: Endpoint,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_codes: Vec<u16>,
}

pub fn one() -> usize {
    1
}
pub fn is_one(value: &usize) -> bool {
    *value == 1
}

pub fn compile_async_api(
    rules: &BTreeMap<String, AsyncApiRules>,
) -> Result<BTreeMap<String, AsyncApiRules>> {
    ensure!(rules.len() <= 256, "async_api exceeds 256 API selectors");
    let mut normalized = rules.clone();
    for (api, scenarios) in &mut normalized {
        super::compiler::validate_api(api)?;
        ensure!(
            !api.starts_with("MOTAN "),
            "async_api lifecycle requires an HTTP API"
        );
        ensure!(
            (1..=32).contains(&scenarios.len()),
            "async API requires 1..32 scenarios"
        );
        for rule in &mut scenarios.0 {
            ensure!(
                rule.when.len() + rule.when_response.len() + rule.unless_response.len() <= 32,
                "async API condition exceeds 32 fields"
            );
            for (pointer, value) in rule
                .when
                .iter()
                .chain(&rule.when_response)
                .chain(&rule.unless_response)
            {
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
                        let tokens =
                            traffic_protocol_mysql_sql::sql::bounds::statement(&end.sql)
                                .context("async MySQL completion requires one SQL statement")?;
                        ensure!(
                            !tokens.is_empty()
                                && !matches!(
                                    tokens.first(),
                                    Some(traffic_protocol_mysql_sql::sql::Token::Placeholder)
                                ),
                            "async MySQL completion requires concrete SQL tokens"
                        );
                        for (index, _) in tokens.iter().enumerate().filter(|(_, token)| {
                            matches!(token, traffic_protocol_mysql_sql::sql::Token::Placeholder)
                        }) {
                            ensure!(
                                index > 0
                                    && !["from", "into", "update", "join", "table", "as", "."]
                                        .iter()
                                        .any(|word| tokens[index - 1].is(word)),
                                "SQL ? matches one scalar value, never a physical identifier"
                            );
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
                        ensure!(
                            end.database.is_none_or(|database| database >= 0),
                            "async Redis database must be nonnegative"
                        );
                        if let Some(endpoint) = &end.endpoint {
                            endpoint.validate()?;
                        }
                    }
                    AsyncEnd::RedisPublish(end) => redis_publish::validate(end)?,
                    AsyncEnd::Http(end) => {
                        let method: hyper::Method = end
                            .method
                            .to_ascii_uppercase()
                            .parse()
                            .context("invalid async HTTP method")?;
                        end.method = method.as_str().to_owned();
                        end.endpoint.validate()?;
                        let uri: hyper::Uri =
                            end.path.parse().context("invalid async HTTP path")?;
                        ensure!(
                            end.path.starts_with('/')
                                && end.path.len() <= 8192
                                && uri.scheme().is_none()
                                && uri.authority().is_none()
                                && uri.query().is_none(),
                            "async HTTP completion requires a bounded absolute path without query or authority"
                        );
                        ensure!(
                            end.status_codes.len() <= 100
                                && end
                                    .status_codes
                                    .iter()
                                    .all(|code| (200..=299).contains(code)),
                            "async HTTP completion requires successful 2xx status codes"
                        );
                        end.status_codes.sort_unstable();
                        end.status_codes.dedup();
                    }
                }
            }
        }
    }
    Ok(normalized)
}

pub fn async_response_matches(rule: &AsyncApiRule, body: Option<&Value>) -> bool {
    let matches = |fields: &BTreeMap<String, Value>| {
        fields
            .iter()
            .all(|(pointer, value)| body.and_then(|body| body.pointer(pointer)) == Some(value))
    };
    matches(&rule.when_response)
        && (rule.unless_response.is_empty() || !matches(&rule.unless_response))
}

pub fn async_api_matches(
    api: &str,
    rule: &AsyncApiRule,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> bool {
    let (Ok((expected_method, path)), Ok(method), Ok(uri)) = (
        traffic_protocol_http::path_pattern::api_selector(api),
        method.parse::<hyper::Method>(),
        uri.parse::<hyper::Uri>(),
    ) else {
        return false;
    };
    let valid_path = if expected_method.as_str() == "MOTAN" && path == "/" {
        Ok(())
    } else if expected_method.as_str() == "MOTAN" {
        traffic_protocol_http::path_pattern::validate_path_pattern(path)
    } else {
        traffic_protocol_http::path_pattern::validate_path_selector(path)
    };
    valid_path.is_ok()
        && expected_method == method
        && traffic_protocol_http::path_pattern::matches_path_pattern(path, uri.path())
        && rule
            .when
            .iter()
            .all(|(pointer, value)| body.and_then(|body| body.pointer(pointer)) == Some(value))
}
