//! Typed traffic-policy/v1 rules. Authoring defaults expand before compilation.
use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const POLICY_FORMAT: &str = "traffic-policy/v1";

#[derive(Debug, Clone, PartialEq)]
pub struct TrafficPolicy {
    pub format: String,
    pub source_revision: Option<String>,
    pub rules: Vec<super::PolicyRule>,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "SlotDocument", into = "SlotDocument")]
pub enum Slot {
    Body,
    /// Strict SSE envelope with JSON contracts on its data string.
    SseData(SseSelector),
    Value,
    SqlValue(usize),
    SqlColumn(String),
}

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

    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.event() == other.event()
            && match (self.json_type(), other.json_type()) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

impl Slot {
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SseData(a), Self::SseData(b)) => a.overlaps(b),
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
}

impl MatchSpec {
    pub fn matches_api(&self, method: &str, path: &str) -> bool {
        self.api.as_ref().is_none_or(|api| {
            api.split_once(' ')
                .is_some_and(|(expected_method, expected_path)| {
                    expected_method == method
                        && (expected_path == path
                            || crate::path_pattern::matches_path_pattern(expected_path, path))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "CodecDocument", into = "CodecDocument")]
pub enum Codec {
    Json,
    Protobuf(ProtobufCodec),
}

impl Codec {
    pub fn is_json(&self) -> bool {
        matches!(self, Self::Json)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtobufCodec {
    pub fields: BTreeMap<String, ProtobufField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtobufField {
    pub field_path: Vec<u32>,
    pub field_type: ProtobufType,
    #[serde(default)]
    pub repeated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtobufType {
    String,
    Message,
    Bytes,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Bool,
    Enum,
    Float,
    Double,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum CodecDocument {
    Builtin(JsonCodecName),
    Protobuf(ProtobufDocument),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum JsonCodecName {
    #[serde(rename = "json")]
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ProtobufCodecName {
    #[serde(rename = "protobuf")]
    Protobuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtobufDocument {
    kind: ProtobufCodecName,
    #[serde(deserialize_with = "unique_map")]
    fields: BTreeMap<String, ProtobufField>,
}

impl From<CodecDocument> for Codec {
    fn from(value: CodecDocument) -> Self {
        match value {
            CodecDocument::Builtin(_) => Self::Json,
            CodecDocument::Protobuf(value) => Self::Protobuf(ProtobufCodec {
                fields: value.fields,
            }),
        }
    }
}

impl From<Codec> for CodecDocument {
    fn from(value: Codec) -> Self {
        match value {
            Codec::Json => Self::Builtin(JsonCodecName::Json),
            Codec::Protobuf(value) => Self::Protobuf(ProtobufDocument {
                kind: ProtobufCodecName::Protobuf,
                fields: value.fields,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldContract {
    /// The inactive branch compares the selected field exactly.
    Conditional {
        when: FieldCondition,
        contract: Box<FieldContract>,
    },
    Unordered,
    /// Source-proven generated/derived identity, shared within one interaction.
    Identity {
        binding: String,
        #[serde(default)]
        prefix: String,
        format: IdentityFormat,
    },
    Time {
        format: TimestampFormat,
        relation: TimeRelation,
        #[serde(skip)]
        anchor: TimeAnchor,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        utc_offset: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clock_group: Option<String>,
    },
    Duration {
        unit: DurationUnit,
        #[serde(skip)]
        anchor: TimeAnchor,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "IdentityFormatDocument", into = "IdentityFormatDocument")]
pub enum IdentityFormat {
    Decimal,
    Uuid,
    /// Exact number of lowercase hexadecimal characters after the literal prefix.
    Hex(usize),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum IdentityFormatDocument {
    Named(IdentityFormatName),
    Hex { hex: usize },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityFormatName {
    Decimal,
    Uuid,
}

impl From<IdentityFormatDocument> for IdentityFormat {
    fn from(value: IdentityFormatDocument) -> Self {
        match value {
            IdentityFormatDocument::Named(IdentityFormatName::Decimal) => Self::Decimal,
            IdentityFormatDocument::Named(IdentityFormatName::Uuid) => Self::Uuid,
            IdentityFormatDocument::Hex { hex } => Self::Hex(hex),
        }
    }
}

impl From<IdentityFormat> for IdentityFormatDocument {
    fn from(value: IdentityFormat) -> Self {
        match value {
            IdentityFormat::Decimal => Self::Named(IdentityFormatName::Decimal),
            IdentityFormat::Uuid => Self::Named(IdentityFormatName::Uuid),
            IdentityFormat::Hex(hex) => Self::Hex { hex },
        }
    }
}

impl FieldContract {
    pub fn unconditional(&self) -> &Self {
        match self {
            Self::Conditional { contract, .. } => contract,
            other => other,
        }
    }

    pub fn time(&self) -> Option<TimeContract> {
        match self {
            Self::Time {
                format,
                relation,
                anchor,
                utc_offset,
                clock_group,
            } => Some(TimeContract {
                format: *format,
                relation: *relation,
                anchor: *anchor,
                utc_offset: utc_offset.clone(),
                clock_group: clock_group.clone(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldCondition {
    /// One parent step followed by an exact JSON Pointer, e.g. ../status.
    pub relative_pointer: String,
    #[serde(
        default,
        deserialize_with = "present_scalar",
        skip_serializing_if = "Option::is_none"
    )]
    pub equals: Option<SourceScalar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_in: Vec<SourceScalar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeContract {
    pub format: TimestampFormat,
    pub relation: TimeRelation,
    #[serde(skip)]
    pub anchor: TimeAnchor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_group: Option<String>,
}

impl TimeContract {
    pub fn offset(&self) -> Result<Option<chrono::FixedOffset>> {
        let Some(value) = &self.utc_offset else {
            // A shared civil offset cancels in a relative comparison and in
            // delivery translation. UTC is only a neutral arithmetic origin.
            if self.relation == TimeRelation::PreserveOffset
                && matches!(
                    self.format,
                    TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime
                )
            {
                return Ok(chrono::FixedOffset::east_opt(0));
            }
            return Ok(None);
        };
        ensure!(
            value.len() == 6
                && matches!(value.as_bytes()[0], b'+' | b'-')
                && value.as_bytes()[3] == b':'
                && value.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
                && value.as_bytes()[4..6].iter().all(u8::is_ascii_digit),
            "utc_offset requires explicit +/-HH:MM"
        );
        let hours: i32 = value[1..3].parse()?;
        let minutes: i32 = value[4..6].parse()?;
        ensure!(
            hours < 24 && minutes < 60,
            "utc_offset is outside a fixed day's range"
        );
        let sign = if value.starts_with('-') { -1 } else { 1 };
        Ok(Some(
            chrono::FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60))
                .context("invalid fixed utc_offset")?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampFormat {
    UnixSeconds,
    UnixMilliseconds,
    UnixMicroseconds,
    Rfc3339,
    AmzDate,
    Iso8601Naive,
    SqlDatetime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRelation {
    RequestWindow,
    PreserveOffset,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TimeAnchor {
    #[serde(rename = "case.request_start")]
    ApiRequestStart,
    #[default]
    #[serde(rename = "dependency.request_start")]
    DependencyRequestStart,
    #[serde(rename = "dependency.response_delivery")]
    DependencyDelivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurationUnit {
    Seconds,
    Milliseconds,
    Microseconds,
    Minutes,
    Hours,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SourceScalar {
    Bool(bool),
    Number(serde_json::Number),
    String(String),
}

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

fn unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct MapVisitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for MapVisitor<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with unique field selectors")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, T>()? {
                if values.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate selector {key:?}"
                    )));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(MapVisitor(std::marker::PhantomData))
}

fn present_scalar<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<SourceScalar>, D::Error> {
    SourceScalar::deserialize(deserializer).map(Some)
}
