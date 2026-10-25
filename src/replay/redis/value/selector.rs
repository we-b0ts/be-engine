//! Public selectors shared by discovery, policy and coordinator authoring.
use crate::replay::policy::{ProtobufFieldPath, ProtobufRepeatedElementType};
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisUnorderedSelector {
    pub host: String,
    pub port: u16,
    pub key: RedisValueKeySelector,
    pub field: RedisUnorderedField,
}
