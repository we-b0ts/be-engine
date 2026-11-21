use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtobufCodec {
    pub fields: BTreeMap<String, ProtobufField>,
}

impl ProtobufCodec {
    /// Immediate elements of repeated scalars retain their declared wire type.
    /// Message descendants require their own declared aliases.
    pub fn field(&self, path: &str) -> Option<ProtobufField> {
        if let Some(field) = self.fields.get(path) {
            return Some(field.clone());
        }
        let (parent, element) = path.rsplit_once('/')?;
        let indexed = element
            .parse::<usize>()
            .ok()
            .is_some_and(|index| index.to_string() == element);
        if element != "*" && !indexed {
            return None;
        }
        let field = self.fields.get(parent)?;
        if !field.repeated || field.field_type == ProtobufType::Message {
            return None;
        }
        let mut field = field.clone();
        field.repeated = false;
        Some(field)
    }
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
