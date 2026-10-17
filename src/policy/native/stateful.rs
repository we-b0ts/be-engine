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
        timezone: String,
    },
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
    Jwt {
        algorithm: SignatureAlgorithm,
        signing_key: StartupKey,
        relative_to: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nonces: Vec<Proven<NonceClaim>>,
    },
    Identity(IdentityReference),
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
        binding: String,
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
    pub binding: String,
    pub template: String,
    pub transform: IdentityTransform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityTransform {
    Identity,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishIdentityEffect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid_field: Option<String>,
}

impl NativeKeySelector {
    pub fn exact(&self) -> Option<&str> {
        match self {
            Self::Exact { value } => Some(value),
            _ => None,
        }
    }
}
