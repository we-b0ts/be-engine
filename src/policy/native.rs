//! Closed contracts for stateful identities, signatures and acquisition effects.
//! The compiler retains these as typed effects; protocol owners never reparse YAML.
mod input;
mod response;
mod source;
mod stateful;

pub use input::*;
pub use response::*;
pub use source::*;
pub use stateful::*;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{Proof, Resource, Rule, SourceCondition};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PolicyRule {
    Value(Box<Rule>),
    Native(Box<NativeRule>),
}

// Dispatch by the explicit native `effect` field rather than an untagged trial
// decoder, so worker errors name the malformed field in the selected rule.
impl<'de> Deserialize<'de> for PolicyRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_yaml::Value::deserialize(deserializer)?;
        let id = value
            .get("id")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("<missing-id>")
            .to_owned();
        crate::policy::authoring::expand_rule(&mut value, None)
            .map_err(|error| serde::de::Error::custom(format!("rule {id:?}: {error:#}")))?;
        if value.get("effect").is_some() {
            serde_yaml::from_value::<NativeRule>(value).map(|rule| Self::Native(Box::new(rule)))
        } else {
            serde_yaml::from_value::<Rule>(value).map(|rule| Self::Value(Box::new(rule)))
        }
        .map_err(|error| serde::de::Error::custom(format!("rule {id:?}: {error}")))
    }
}

impl PolicyRule {
    pub fn as_value(&self) -> Option<&Rule> {
        if let Self::Value(rule) = self {
            Some(rule)
        } else {
            None
        }
    }
    pub fn as_value_mut(&mut self) -> Option<&mut Rule> {
        if let Self::Value(rule) = self {
            Some(rule)
        } else {
            None
        }
    }
    pub fn as_native(&self) -> Option<&NativeRule> {
        if let Self::Native(rule) = self {
            Some(rule)
        } else {
            None
        }
    }
    pub fn id(&self) -> &str {
        match self {
            Self::Value(rule) => &rule.id,
            Self::Native(rule) => &rule.id,
        }
    }

    pub fn proof(&self) -> &Proof {
        match self {
            Self::Value(rule) => &rule.proof,
            Self::Native(rule) => &rule.proof,
        }
    }
}

impl From<Rule> for PolicyRule {
    fn from(rule: Rule) -> Self {
        Self::Value(Box::new(rule))
    }
}

impl From<NativeRule> for PolicyRule {
    fn from(rule: NativeRule) -> Self {
        Self::Native(Box::new(rule))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRule {
    pub id: String,
    #[serde(rename = "match")]
    pub selector: NativeMatch,
    pub effect: NativeEffect,
    pub proof: Proof,
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
    pub table_series: Option<crate::MysqlTableSeries>,
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

/// Every nested relaxation retains its resolved proof in the IR. Authoring may
/// inherit that proof locally, including bindings in a sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proven<T> {
    pub contract: T,
    pub proof: Proof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeEffect {
    Identity(IdentityEffect),
    RedisSequence(RedisSequenceEffect),
    RedisAppendStream,
    RedisLock,
    RedisPublishIdentity(PublishIdentityEffect),
    ResponseJwt(ResponseJwtEffect),
    ResponseHeaderDate(HeaderDateEffect),
    ResponseGenerated(GeneratedEffect),
    ResponseBody(BodyEffect),
    HttpRequest(HttpRequestEffect),
    MysqlValues(MysqlValuesEffect),
    InputJwt(InputJwtEffect),
    InputSignedTimestamp(InputSignedTimestampEffect),
    CaptureHttp(CaptureHttpEffect),
    CaptureBreeze(CaptureBreezeEffect),
    CaptureHttpResponse(CaptureResponseEffect),
    ProcessOwned(ProcessOwnedEffect),
    FiniteSharing(FiniteSharingEffect),
}

impl NativeEffect {
    pub(crate) fn redis_read_back(&self) -> &[Proven<RedisReadBack>] {
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
    pub(crate) fn as_json(&self) -> serde_json::Value {
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
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub headers: BTreeMap<String, Proven<NativeTime>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub query: BTreeMap<String, Proven<GeneratedValue>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub json: BTreeMap<String, Proven<HttpJsonField>>,
    #[serde(default)]
    pub multipart_boundary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HttpJsonField {
    Random {
        format: RandomEncoding,
        length: usize,
    },
    Jwt {
        algorithm: SignatureAlgorithm,
        signing_key: StartupKey,
        #[serde(skip)]
        anchor: crate::policy::TimeAnchor,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nonces: Vec<Proven<NonceClaim>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlValuesEffect {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub params: BTreeMap<usize, Proven<GeneratedValue>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub values: BTreeMap<usize, Proven<SqlValueContract>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub response_time: BTreeMap<String, Proven<SqlResponseTime>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlResponseTime {
    pub time: NativeTime,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserve_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlValueContract {
    Time(NativeTime),
    Json {
        #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
        fields: BTreeMap<String, Proven<NativeTime>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedValue {
    Bind {
        binding: String,
    },
    Uuid {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding: Option<String>,
    },
    UuidV4 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding: Option<String>,
    },
    NonEmpty {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding: Option<String>,
    },
    Reference {
        binding: String,
    },
    Time(NativeTime),
}
