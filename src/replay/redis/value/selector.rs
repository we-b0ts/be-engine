//! Public selectors shared by discovery, policy and coordinator authoring.
use crate::replay::policy::{
    ProtobufFieldPath, ProtobufRepeatedElementType, ProtobufUnorderedPath,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub use super::super::key_selector::RedisValueKeySelector;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "codec", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedisUnorderedField {
    Json {
        pointer: String,
    },
    Protobuf {
        field_path: ProtobufFieldPath,
        element_type: ProtobufRepeatedElementType,
        display_path: String,
    },
}
impl RedisUnorderedField {
    pub(in crate::replay) fn protobuf_rule(&self) -> Option<ProtobufUnorderedPath> {
        match self {
            Self::Protobuf {
                field_path,
                element_type,
                display_path,
            } => Some(ProtobufUnorderedPath {
                field_path: field_path.clone(),
                element_type: *element_type,
                display_path: display_path.clone(),
                source_evidence: String::new(),
            }),
            _ => None,
        }
    }
    pub(in crate::replay) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Json { pointer: a }, Self::Json { pointer: b }) => {
                a.is_empty()
                    || b.is_empty()
                    || crate::replay::policy::response_locations_overlap(a, b)
            }
            (Self::Protobuf { field_path: a, .. }, Self::Protobuf { field_path: b, .. }) => {
                a.0.starts_with(&b.0) || b.0.starts_with(&a.0)
            }
            _ => false,
        }
    }
    pub(in crate::replay) fn selects(&self, candidate: &Self) -> bool {
        match (self, candidate) {
            (Self::Json { pointer: a }, Self::Json { pointer: b }) => {
                a == b || crate::replay::policy::response_pointer_matches(a, b)
            }
            (
                Self::Protobuf {
                    field_path: a,
                    element_type: at,
                    ..
                },
                Self::Protobuf {
                    field_path: b,
                    element_type: bt,
                    ..
                },
            ) => a == b && at == bt,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisUnorderedSelector {
    pub host: String,
    pub port: u16,
    pub key: RedisValueKeySelector,
    pub field: RedisUnorderedField,
}
impl RedisUnorderedSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.trim().is_empty()
                && self.host.len() <= 253
                && !self.host.contains(['*', '/', ' ', '\n'])
                && self.port != 0,
            "Redis unordered requires an exact host and nonzero port"
        );
        self.key.validate()?;
        match &self.field {
            RedisUnorderedField::Json { pointer } if !pointer.is_empty() => {
                crate::replay::policy::validate_json_pointer(pointer)?
            }
            RedisUnorderedField::Protobuf {
                field_path,
                display_path,
                ..
            } => {
                ensure!(
                    !field_path.0.is_empty()
                        && field_path.0.len() <= 32
                        && field_path.0.iter().all(|n| (1..(1 << 29)).contains(n)),
                    "invalid Redis protobuf field path"
                );
                ensure!(
                    !display_path.trim().is_empty()
                        && display_path.len() <= 256
                        && *display_path != field_path.display_path(),
                    "Redis protobuf requires a semantic display path"
                );
            }
            _ => {}
        }
        Ok(())
    }
    pub(in crate::replay) fn matches(&self, host: &str, port: u16, key: &[u8]) -> bool {
        self.host.eq_ignore_ascii_case(host) && self.port == port && self.key.matches(key)
    }
    pub(in crate::replay) fn selects(&self, candidate: &Self) -> bool {
        let RedisValueKeySelector::Exact { value } = &candidate.key else {
            return false;
        };
        self.matches(&candidate.host, candidate.port, value.as_bytes())
            && self.field.selects(&candidate.field)
    }
}
