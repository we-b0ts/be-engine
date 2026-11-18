//! Typed persisted effects for existing traffic-policy declarations.
mod input;
mod read_back;
mod response;
mod source;
mod stateful;
use crate::{Proof, Resource, SourceCondition};
pub use input::*;
pub use read_back::is_key_only_read_back;
pub use response::*;
use serde::{Deserialize, Serialize};
pub use source::*;
pub use stateful::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRule {
    pub id: String,
    #[serde(rename = "match")]
    pub selector: NativeMatch,
    pub effect: NativeEffect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<SourceCondition>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    #[serde(default, rename = "host", skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<NativeKeySelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_series: Option<traffic_protocol_mysql::table_selector::MysqlTableSeries>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeKeySelector {
    Exact {
        value: String,
    },
    Affix {
        prefix: String,
        #[serde(default)]
        suffix: String,
    },
    Numeric {
        prefix: String,
        #[serde(default)]
        suffix: String,
    },
}

/// Plan proposals may attach Source evidence. Runtime contracts need only the
/// declared behavior; absence of evidence is represented explicitly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proven<T> {
    pub contract: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeEffect {
    Identity(IdentityEffect),
    RedisSequence(RedisSequenceEffect),
    RedisAppendStream,
    RedisReadCommutation(RedisReadCommutationEffect),
    RedisReadObservation(RedisReadObservationEffect),
    RedisExpiryRefresh(RedisExpiryRefreshEffect),
    RedisActivityRefresh(RedisActivityRefreshEffect),
    ResponseJwt(ResponseJwtEffect),
    ResponseHeaderDate(HeaderDateEffect),
    ResponseGenerated(GeneratedEffect),
    ResponseBody(BodyEffect),
    HttpRequest(HttpRequestEffect),
    MysqlValues(MysqlValuesEffect),
    InputJwt(InputJwtEffect),
    InputSignedTimestamp(InputSignedTimestampEffect),
    CaptureHttp(CaptureHttpEffect),
    CaptureHttpResponse(CaptureResponseEffect),
    ProcessOwned(ProcessOwnedEffect),
    FiniteSharing(FiniteSharingEffect),
}

impl NativeEffect {
    pub fn redis_read_back(&self) -> &[Proven<RedisReadBack>] {
        match self {
            Self::Identity(effect) => &effect.read_back,
            Self::RedisSequence(effect) => &effect.read_back,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StartupKey {
    TargetEnv { name: String },
    TargetFile { path: String, field: String },
}

/// SQL parameters and origin predicates admit scalar literals, never payload blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Literal {
    Null(()),
    Bool(bool),
    Integer(i64),
    String(String),
}

impl Literal {
    pub fn as_json(&self) -> serde_json::Value {
        match self {
            Self::Null(()) => serde_json::Value::Null,
            Self::Bool(value) => (*value).into(),
            Self::Integer(value) => (*value).into(),
            Self::String(value) => value.clone().into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NonceFormat {
    UuidV4,
    Base64url { decoded_bytes: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceClaim {
    pub pointer: String,
    pub format: NonceFormat,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputJwtEffect {
    pub location: InputTokenLocation,
    pub algorithm: SignatureAlgorithm,
    pub signing_key: StartupKey,
    pub time: InputTokenTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputTokenLocation {
    BearerHeader { name: String },
    RawHeader { name: String },
    Query { name: String },
    SocketIoConnect { namespace: String, pointer: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputTokenTime {
    PreserveRelative,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestEffect {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub query: BTreeMap<String, Proven<GeneratedValue>>,
    #[serde(default)]
    pub multipart_boundary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlValuesEffect {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub params: BTreeMap<usize, Proven<GeneratedValue>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub values: BTreeMap<usize, Proven<SqlValueContract>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlValueContract {
    Time(NativeTime),
    Json {
        #[serde(deserialize_with = "crate::strict_map::unique_map")]
        fields: BTreeMap<String, Proven<NativeTime>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedValue {
    Uuid {},
    UuidV4 {},
    NonEmpty {},
    Time(NativeTime),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDomain {
    Runtime,
    Input,
    Capture,
    Classification,
}

impl NativeEffect {
    pub fn domain(&self) -> NativeDomain {
        match self {
            Self::InputJwt(_) | Self::InputSignedTimestamp(_) => NativeDomain::Input,
            Self::CaptureHttp(_) | Self::CaptureHttpResponse(_) => NativeDomain::Capture,
            Self::ProcessOwned(_) => NativeDomain::Classification,
            _ => NativeDomain::Runtime,
        }
    }

    pub fn capability_name(&self) -> &'static str {
        match self {
            Self::Identity(_) => "identity",
            Self::RedisSequence(_) => "atomic_request_sequence",
            Self::RedisAppendStream => "append_stream_equivalence",
            Self::RedisReadCommutation(_) => "finite_read_commutation",
            Self::RedisReadObservation(effect) if effect.state_values => "key_state_observation",
            Self::RedisReadObservation(_) => "key_lifetime_absent_read",
            Self::RedisExpiryRefresh(_) => "key_lifetime_expiry_refresh",
            Self::RedisActivityRefresh(_) => "key_lifetime_activity_refresh",
            Self::ResponseJwt(_) => "signed_response",
            Self::ResponseHeaderDate(_) => "header_calendar_date",
            Self::ResponseGenerated(_) => "generated_response",
            Self::ResponseBody(_) => "structured_response",
            Self::HttpRequest(_) => "http_request_contract",
            Self::MysqlValues(_) => "sql_value_contract",
            Self::InputJwt(_) => "input_token_rebase",
            Self::InputSignedTimestamp(_) => "input_signed_timestamp_rebase",
            Self::CaptureHttp(_) => "capture_http_scope",
            Self::CaptureHttpResponse(_) => "capture_response_urls",
            Self::ProcessOwned(_) => "process_ownership",
            Self::FiniteSharing(_) => "finite_recording_sharing",
        }
    }
}
