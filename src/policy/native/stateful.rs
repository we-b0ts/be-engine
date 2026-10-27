//! Stateful effects preserve one atomic decision and commit boundary.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{NativeKeySelector, NonceClaim, Proven, SignatureAlgorithm, StartupKey};
use crate::policy::Resource;
pub use crate::policy::TimeContract as NativeTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEffect {
    pub value_type: IdentityType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<IdentityFormat>,
    pub capture: IdentityCapture,
    pub references: Vec<Proven<IdentityTarget>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_back: Vec<Proven<RedisReadBack>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    String,
    Integer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityFormat {
    Uuid,
    UuidV4,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityCapture {
    MysqlValue {
        index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
    },
    RedisArgument {
        index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        when: Option<crate::policy::FieldCondition>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        copies: Vec<Proven<JsonIdentityCopy>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derived_from: Option<Proven<DerivedIdentity>>,
    },
    HttpJson {
        pointer: String,
    },
    HttpPath {
        segment: PathIdentitySegment,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityTarget {
    pub resource: Resource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonIdentityCopy {
    pub pointer: String,
    pub template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedIdentity {
    pub pointer: String,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathIdentitySegment {
    pub index: usize,
    pub template: String,
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub fields: BTreeMap<String, Proven<PathIdentityField>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathIdentityField {
    Exact,
    Random {
        format: PathRandomFormat,
        length: usize,
    },
    Timestamp {
        format: String,
        #[serde(default = "utc_timezone")]
        timezone: String,
        #[serde(default)]
        mode: PathTimestampMode,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTimestampMode {
    RequestWindow,
    #[default]
    PreserveOrRequestWindow,
}

fn utc_timezone() -> String {
    "UTC".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathRandomFormat {
    Base64url,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisSequenceEffect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Proven<NativeKeyContract>>,
    pub commands: Vec<SequenceCommand>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_back: Vec<Proven<RedisReadBack>>,
}

/// No optional/reusable modes: every selected read stays finite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisReadCommutationEffect {}

/// Explicitly normalize successful fixed-TTL refreshes within one key lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisExpiryRefreshEffect {}

/// Only declared JSON timestamp leaves may change during a key's refresh lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisActivityRefreshEffect {
    pub fields: Vec<String>,
}

/// An explicit same-key read may return selected values from a matched write.
/// Empty pointers select a raw bulk value; nonempty pointers select JSON scalars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisReadBack {
    pub operation: String,
    pub write_operation: String,
    pub argument_index: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub json_pointers: Vec<String>,
    /// Source proof that GET observes the current SET/DEL state, rather than a
    /// required invocation count. Absent declarations retain finite reads.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub state_epochs: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceCommand {
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<Proven<ScriptIdentity>>,
    #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
    pub arguments: BTreeMap<usize, Proven<SequenceArgument>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SequenceArgument {
    Time(NativeTime),
    Json {
        #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
        fields: BTreeMap<String, Proven<SequenceField>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SequenceField {
    Time(NativeTime),
    Random {
        format: super::RandomEncoding,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_length: Option<usize>,
    },
    Url {
        #[serde(deserialize_with = "crate::policy::strict_map::unique_map")]
        query: BTreeMap<String, Proven<SequenceUrlField>>,
    },
    Jwt {
        algorithm: SignatureAlgorithm,
        signing_key: StartupKey,
        relative_to: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nonces: Vec<Proven<NonceClaim>>,
    },
    Identity(IdentityReference),
}

/// Selected URL query values; the complete URL remainder stays exact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SequenceUrlField {
    Time(NativeTime),
    UtcDateSegment(UtcDateSegment),
    Random {
        format: super::RandomEncoding,
        length: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtcDateSegment {
    pub separator: char,
    pub index: usize,
    pub relative_to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeKeyContract {
    TimeWindow {
        window_seconds: u32,
        separator: char,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segment_index: Option<usize>,
    },
    Capture {
        template: String,
        format: KeyIdentityFormat,
    },
    Reference(IdentityReference),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyIdentityFormat {
    Hex { bytes: usize },
    Base64url { bytes: usize },
    UuidV4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReference {
    pub template: String,
    pub transform: IdentityTransform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTransform {
    Identity,
    Sha256,
}

impl NativeKeySelector {
    pub fn exact(&self) -> Option<&str> {
        match self {
            Self::Exact { value } => Some(value),
            _ => None,
        }
    }
}
