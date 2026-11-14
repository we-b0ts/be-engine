//! Content strategy declarations are independent of physical protocol locations.
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "CodecDocument", into = "CodecDocument")]
pub enum Codec {
    Scalar,
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
    Builtin(BuiltinCodecName),
    Protobuf(ProtobufDocument),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum BuiltinCodecName {
    #[serde(rename = "scalar")]
    Scalar,
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
            CodecDocument::Builtin(BuiltinCodecName::Json) => Self::Json,
            CodecDocument::Builtin(BuiltinCodecName::Scalar) => Self::Scalar,
            CodecDocument::Protobuf(value) => Self::Protobuf(ProtobufCodec {
                fields: value.fields,
            }),
        }
    }
}

impl From<Codec> for CodecDocument {
    fn from(value: Codec) -> Self {
        match value {
            Codec::Json => Self::Builtin(BuiltinCodecName::Json),
            Codec::Scalar => Self::Builtin(BuiltinCodecName::Scalar),
            Codec::Protobuf(value) => Self::Protobuf(ProtobufDocument {
                kind: ProtobufCodecName::Protobuf,
                fields: value.fields,
            }),
        }
    }
}

pub fn unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
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
