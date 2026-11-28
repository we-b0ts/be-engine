//! Typed Protobuf decoding and lossless wire reconstruction behind an open codec.
use std::{borrow::Cow, sync::Arc};

use anyhow::{Result, ensure};
use traffic_value::{
    Value,
    codec::{CodecDescriptor, CodecProvider, Recognition, ValueCodec, ValueDocument},
};

mod types;
pub use types::{ProtobufCodec, ProtobufField, ProtobufType};
mod wire_document;

use traffic_value::path::{escape, matches as pointer_matches};

pub const REMAINDER_KEY: &str = wire_document::INTERNAL_KEY;
pub struct ProtobufProvider;

impl CodecProvider for ProtobufProvider {
    fn field_schema(
        &self,
        configuration: &Value,
        path: &str,
    ) -> Result<traffic_value::codec::FieldSchema> {
        use traffic_value::codec::{FieldSchema, ValueType};
        let configuration: ProtobufCodec =
            serde_json::from_value(serde_json::to_value(configuration)?)?;
        let field = configuration.field(path).ok_or_else(|| {
            anyhow::anyhow!("Protobuf contract {path:?} requires an explicit typed field binding")
        })?;
        let value_type = match field.field_type {
            ProtobufType::String => ValueType::String,
            ProtobufType::Message => ValueType::Object,
            ProtobufType::Bytes => ValueType::Bytes,
            ProtobufType::Bool => ValueType::Boolean,
            ProtobufType::Enum => ValueType::Enumeration,
            _ => ValueType::Number,
        };
        let scalar = FieldSchema::Typed(value_type);
        Ok(if field.repeated {
            FieldSchema::Sequence(Box::new(scalar))
        } else {
            scalar
        })
    }

    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "protobuf",
            version: 1,
        }
    }

    fn recognize(&self, _source: &[u8], metadata: &Value) -> Result<Recognition> {
        Ok(match metadata.pointer("/protobuf") {
            Some(configuration) => Recognition::Recognized {
                confidence: 200,
                configuration: configuration.clone(),
            },
            None => Recognition::Candidate {
                reason: "typed Protobuf interpretation requires field bindings".into(),
            },
        })
    }

    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        let configuration: ProtobufCodec =
            serde_json::from_value(serde_json::to_value(configuration)?)?;
        Ok(Arc::new(Prepared {
            schema: wire_document::schema(&configuration)?,
        }))
    }
    fn fields_overlap(
        &self,
        left_configuration: &Value,
        left_path: &str,
        right_configuration: &Value,
        right_path: &str,
    ) -> Result<bool> {
        let left: ProtobufCodec =
            serde_json::from_value(serde_json::to_value(left_configuration)?)?;
        let right: ProtobufCodec =
            serde_json::from_value(serde_json::to_value(right_configuration)?)?;
        let left_field = left
            .field(left_path)
            .ok_or_else(|| anyhow::anyhow!("left field has no typed Protobuf binding"))?;
        let right_field = right
            .field(right_path)
            .ok_or_else(|| anyhow::anyhow!("right field has no typed Protobuf binding"))?;
        if left_field.field_path == right_field.field_path
            && !left.fields.contains_key(left_path)
            && !right.fields.contains_key(right_path)
        {
            let left_element = left_path.rsplit('/').next();
            let right_element = right_path.rsplit('/').next();
            return Ok(left_element == right_element
                || left_element == Some("*")
                || right_element == Some("*"));
        }
        Ok(left_field
            .field_path
            .iter()
            .zip(&right_field.field_path)
            .all(|(left, right)| left == right))
    }
    fn merge(&self, configurations: &[&Value]) -> Result<Value> {
        let first = configurations
            .first()
            .ok_or_else(|| anyhow::anyhow!("Protobuf merge has no schemas"))?;
        let mut merged: ProtobufCodec = serde_json::from_value(serde_json::to_value(first)?)?;
        for configuration in configurations.iter().skip(1) {
            let next: ProtobufCodec = serde_json::from_value(serde_json::to_value(configuration)?)?;
            for (path, field) in next.fields {
                if let Some(current) = merged.fields.get(&path) {
                    ensure!(
                        current == &field,
                        "selected rules disagree on a typed Protobuf field"
                    );
                } else {
                    ensure!(
                        merged
                            .fields
                            .values()
                            .all(|current| current.field_path != field.field_path),
                        "selected rules alias a Protobuf wire field"
                    );
                    merged.fields.insert(path, field);
                }
            }
        }
        Ok(serde_json::from_value(serde_json::to_value(merged)?)?)
    }
}

struct Prepared {
    schema: Arc<wire_document::Schema>,
}

impl ValueCodec for Prepared {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "Protobuf payload exceeds 64 MiB"
        );
        let (wire, logical) = self.schema.decode(bytes)?;
        Ok(Arc::new(Document {
            wire,
            value: serde_json::from_value(logical)?,
            original: bytes.to_vec(),
        }))
    }
}

struct Document {
    wire: wire_document::Document,
    value: Value,
    original: Vec<u8>,
}

impl ValueDocument for Document {
    fn value(&self) -> &Value {
        &self.value
    }
    fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    fn retains_unselected_encoding(&self) -> bool {
        true
    }

    fn comparison_view<'a>(&'a self, selected: &[String]) -> Cow<'a, Value> {
        if selected.is_empty() {
            return Cow::Borrowed(&self.value);
        }
        let mut logical =
            serde_json::to_value(&self.value).expect("decoded Protobuf is serializable");
        wire_document::prepare_comparison(&mut logical, "", selected);
        Cow::Owned(
            serde_json::from_value(logical).expect("decoded Protobuf retains its value categories"),
        )
    }

    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>> {
        traffic_value::validate_patch(&self.value, logical, allowed)?;
        validate_remainders(&self.value, logical)?;
        if logical == &self.value {
            return Ok(self.original.clone());
        }
        let output = self.wire.encode(&serde_json::to_value(logical)?)?;
        ensure!(
            output.len() <= traffic_value::MAX_VALUE_BYTES,
            "derived Protobuf exceeds 64 MiB"
        );
        Ok(output)
    }
}

fn validate_remainders(before: &Value, after: &Value) -> Result<()> {
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            ensure!(
                before.get(REMAINDER_KEY) == after.get(REMAINDER_KEY),
                "delivery changes the Protobuf remainder"
            );
            for (key, value) in before {
                if key != REMAINDER_KEY {
                    validate_remainders(value, &after[key])?;
                }
            }
        }
        (Value::Array(before), Value::Array(after)) => {
            for (before, after) in before.iter().zip(after) {
                validate_remainders(before, after)?;
            }
        }
        _ => {}
    }
    Ok(())
}
