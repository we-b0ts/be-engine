//! Typed physical value bindings and immutable Source predicates.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub surface: Surface,
    #[serde(rename = "match")]
    pub selector: MatchSpec,
    pub slot: Slot,
    pub codec: Codec,
    #[serde(deserialize_with = "unique_map")]
    pub contract: BTreeMap<String, FieldContract>,
    pub proof: Proof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<SourceCondition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Surface {
    #[serde(rename = "api.response")]
    ApiResponse,
    #[serde(rename = "dependency.request")]
    DependencyRequest,
    #[serde(rename = "dependency.response")]
    DependencyResponse,
}

impl Surface {
    pub fn dependency_side(self) -> Result<traffic_protocol::evidence::MessageSide> {
        match self {
            Self::DependencyRequest => Ok(traffic_protocol::evidence::MessageSide::Request),
            Self::DependencyResponse => Ok(traffic_protocol::evidence::MessageSide::Response),
            Self::ApiResponse => {
                anyhow::bail!("API response cannot select a dependency witness payload")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "SlotDocument", into = "SlotDocument")]
pub enum Slot {
    Body,
    /// Strict SSE envelope with JSON contracts on its data string.
    SseData(SseSelector),
    Value,
    SqlValue(usize),
    SqlColumn(String),
    /// A physical column, independent of statement shape or bind position.
    SqlField(String),
    /// The logical value of the selected Redis storage container.
    RedisValue(RedisContainer),
}

pub use traffic_protocol_redis::values::RedisContainer;

/// Select using immutable Source framing and, explicitly, its business JSON type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SseSelector {
    Event(String),
    JsonType { event: String, json_type: String },
}

impl SseSelector {
    pub fn event(&self) -> &str {
        match self {
            Self::Event(event) | Self::JsonType { event, .. } => event,
        }
    }

    pub fn json_type(&self) -> Option<&str> {
        match self {
            Self::Event(_) => None,
            Self::JsonType { json_type, .. } => Some(json_type),
        }
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.event() == other.event()
            && match (self.json_type(), other.json_type()) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

impl Slot {
    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SseData(a), Self::SseData(b)) => a.overlaps(b),
            (Self::SqlField(a), Self::SqlField(b)) => a.eq_ignore_ascii_case(b),
            (Self::RedisValue(_), Self::RedisValue(_) | Self::Value)
            | (Self::Value, Self::RedisValue(_)) => true,
            (Self::SqlField(_), Self::SqlValue(_) | Self::SqlColumn(_))
            | (Self::SqlValue(_) | Self::SqlColumn(_), Self::SqlField(_)) => true,
            _ => self == other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum SlotDocument {
    Named(SlotName),
    SseData { sse_data: SseSelector },
    SqlValue { sql_value: usize },
    SqlColumn { sql_column: String },
    SqlField { sql_field: String },
    RedisValue { redis_value: RedisContainer },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SlotName {
    Body,
    Value,
}

impl From<SlotDocument> for Slot {
    fn from(value: SlotDocument) -> Self {
        match value {
            SlotDocument::Named(SlotName::Body) => Self::Body,
            SlotDocument::Named(SlotName::Value) => Self::Value,
            SlotDocument::SseData { sse_data } => Self::SseData(sse_data),
            SlotDocument::SqlValue { sql_value } => Self::SqlValue(sql_value),
            SlotDocument::SqlColumn { sql_column } => Self::SqlColumn(sql_column),
            SlotDocument::SqlField { sql_field } => Self::SqlField(sql_field),
            SlotDocument::RedisValue { redis_value } => Self::RedisValue(redis_value),
        }
    }
}

impl From<Slot> for SlotDocument {
    fn from(value: Slot) -> Self {
        match value {
            Slot::Body => Self::Named(SlotName::Body),
            Slot::Value => Self::Named(SlotName::Value),
            Slot::SseData(sse_data) => Self::SseData { sse_data },
            Slot::SqlValue(sql_value) => Self::SqlValue { sql_value },
            Slot::SqlColumn(sql_column) => Self::SqlColumn { sql_column },
            Slot::SqlField(sql_field) => Self::SqlField { sql_field },
            Slot::RedisValue(redis_value) => Self::RedisValue { redis_value },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeySelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_field: Option<KeySelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_series: Option<traffic_protocol_mysql_sql::table_selector::MysqlTableSeries>,
}

impl MatchSpec {
    pub fn matches_api(&self, method: &str, path: &str) -> bool {
        self.api.as_ref().is_none_or(|api| {
            api.split_once(' ')
                .is_some_and(|(expected_method, expected_path)| {
                    expected_method == method
                        && (expected_path == path
                            || traffic_protocol_http::path_pattern::matches_path_pattern(
                                expected_path,
                                path,
                            ))
                })
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub protocol: Protocol,
    pub endpoint: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<Database>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Redis,
    Memcached,
    Mysql,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Database {
    Index(i64),
    Name(String),
}

impl Database {
    pub fn index(&self) -> Option<i64> {
        match self {
            Self::Index(value) => Some(*value),
            Self::Name(_) => None,
        }
    }
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name(value) => Some(value),
            Self::Index(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(value: &str) -> Result<Self> {
        let (host, port) = value
            .rsplit_once(':')
            .context("endpoint requires host:port")?;
        let host = if host.starts_with('[') && host.ends_with(']') {
            let address = &host[1..host.len() - 1];
            address
                .parse::<std::net::Ipv6Addr>()
                .context("invalid bracketed IPv6 endpoint")?;
            address
        } else {
            ensure!(!host.contains(':'), "IPv6 endpoints require brackets");
            host
        };
        let endpoint = Self {
            host: host.into(),
            port: port.parse().context("invalid endpoint port")?,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty() && self.host.len() <= 255,
            "endpoint host is empty or too long"
        );
        ensure!(
            !self
                .host
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '*' | '@' | '[' | ']')),
            "endpoint requires one exact host without URL, credentials or wildcard"
        );
        ensure!(self.port > 0, "endpoint port must be nonzero");
        Ok(())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySelector {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub numeric: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
}

impl KeySelector {
    pub fn matches(&self, value: &[u8]) -> bool {
        self.exact
            .as_ref()
            .is_none_or(|exact| value == exact.as_bytes())
            && self
                .prefix
                .as_ref()
                .is_none_or(|prefix| value.starts_with(prefix.as_bytes()))
            && self
                .suffix
                .as_ref()
                .is_none_or(|suffix| value.ends_with(suffix.as_bytes()))
            && (!self.numeric
                || self
                    .prefix
                    .as_ref()
                    .map_or(Some(value), |prefix| value.strip_prefix(prefix.as_bytes()))
                    .and_then(|value| {
                        self.suffix
                            .as_ref()
                            .map_or(Some(value), |suffix| value.strip_suffix(suffix.as_bytes()))
                    })
                    .is_some_and(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit)))
    }
}

pub use traffic_codec_protobuf::{ProtobufCodec, ProtobufField, ProtobufType};
pub use traffic_contract::codec::Codec;
use traffic_contract::codec::unique_map;

pub use traffic_contract::rule::{
    DurationUnit, FieldCondition, FieldContract, IdentityFormat, TimeAnchor, TimeContract,
    TimeRelation, TimestampFormat,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    #[serde(
        default,
        deserialize_with = "super::proof::deserialize_source",
        skip_serializing_if = "String::is_empty"
    )]
    pub source: String,
    pub fact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub rebase_time: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCondition {
    #[serde(deserialize_with = "unique_map")]
    pub request_body_json: BTreeMap<String, SourcePredicate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SourcePredicate {
    Equals(EqualsPredicate),
    NotEquals(NotEqualsPredicate),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EqualsPredicate {
    pub equals: SourceScalar,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotEqualsPredicate {
    pub not_equals: SourceScalar,
}

pub use traffic_contract::rule::SourceScalar;

impl SourceCondition {
    /// Only immutable inbound Source JSON may be supplied by the caller.
    pub fn matches_body(&self, source_body: &serde_json::Value) -> bool {
        self.request_body_json.iter().all(|(pointer, predicate)| {
            let Some(actual) = source_body.pointer(pointer) else {
                return false;
            };
            let (expected, equal) = match predicate {
                SourcePredicate::Equals(value) => (&value.equals, true),
                SourcePredicate::NotEquals(value) => (&value.not_equals, false),
            };
            let matches = match (expected, actual) {
                (SourceScalar::Bool(expected), serde_json::Value::Bool(actual)) => {
                    Some(expected == actual)
                }
                (SourceScalar::Number(expected), serde_json::Value::Number(actual)) => {
                    Some(expected == actual)
                }
                (SourceScalar::String(expected), serde_json::Value::String(actual)) => {
                    Some(expected == actual)
                }
                _ => None,
            };
            matches == Some(equal)
        })
    }
}
