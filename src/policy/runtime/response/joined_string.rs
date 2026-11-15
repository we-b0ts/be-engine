use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::{Hessian2ValuePath, ProtobufFieldPath, ResponseBodyCodec};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct JsonJoinedStringResponseRule {
    pub(crate) pointer: String,
    pub(crate) separator: String,
    pub(crate) source_evidence: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProtobufJoinedStringFieldType {
    String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ProtobufJoinedStringPath {
    pub field_path: ProtobufFieldPath,
    pub display_path: String,
    pub field_type: ProtobufJoinedStringFieldType,
    pub separator: String,
    pub source_evidence: String,
}

/// Selects a Hessian2 string field whose value is a collection joined into
/// one string. Splitting and comparison preserve duplicates and empty items.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Hessian2JoinedStringPath {
    pub value_path: Hessian2ValuePath,
    pub display_path: String,
    pub separator: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(untagged)]
pub enum ResponseBodyJoinedStringPath {
    Protobuf(ProtobufJoinedStringPath),
    Hessian2(Hessian2JoinedStringPath),
}

impl<'de> Deserialize<'de> for ResponseBodyJoinedStringPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match (
            value.get("field_path").is_some(),
            value.get("value_path").is_some(),
        ) {
            (true, false) => serde_json::from_value(value)
                .map(Self::Protobuf)
                .map_err(D::Error::custom),
            (false, true) => serde_json::from_value(value)
                .map(Self::Hessian2)
                .map_err(D::Error::custom),
            (true, true) => Err(D::Error::custom(
                "response-body joined-string path cannot contain both field_path and value_path",
            )),
            (false, false) => Err(D::Error::custom(
                "response-body joined-string path requires field_path or value_path",
            )),
        }
    }
}

impl ResponseBodyJoinedStringPath {
    pub fn codec(&self) -> ResponseBodyCodec {
        match self {
            Self::Protobuf(_) => ResponseBodyCodec::Protobuf,
            Self::Hessian2(_) => ResponseBodyCodec::Hessian2,
        }
    }

    pub fn display_path(&self) -> &str {
        match self {
            Self::Protobuf(path) => &path.display_path,
            Self::Hessian2(path) => &path.display_path,
        }
    }

    pub fn separator(&self) -> &str {
        match self {
            Self::Protobuf(path) => &path.separator,
            Self::Hessian2(path) => &path.separator,
        }
    }
}

pub(super) fn validate_separator(separator: &str, label: &str) -> Result<()> {
    ensure!(!separator.is_empty(), "{label} must not be empty");
    ensure!(
        !separator.contains(['\r', '\n']),
        "{label} must be a single line"
    );
    ensure!(separator.len() <= 16, "{label} exceeds 16 bytes");
    Ok(())
}
