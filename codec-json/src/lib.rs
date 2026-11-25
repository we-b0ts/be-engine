//! Strict JSON recognition, logical projection and token-preserving delivery.
use std::{borrow::Cow, sync::Arc};

use anyhow::{Context, Result, ensure};
use traffic_value::{
    Value,
    codec::{CodecDescriptor, CodecProvider, Recognition, ValueCodec, ValueDocument},
};

mod parse;
pub use parse::{parse, parse_with_limit};
pub mod render;

pub const MAX_VALUE_BYTES: usize = traffic_value::MAX_VALUE_BYTES;

/// Stable JSON object spelling for native document fingerprints.
pub fn canonical(value: &serde_json::Value) -> Vec<u8> {
    fn ordered(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(fields) => serde_json::Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), ordered(value)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.iter().map(ordered).collect())
            }
            value => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).expect("JSON values are serializable")
}

pub struct JsonCodec;
pub struct JsonScalarCodec;

impl CodecProvider for JsonScalarCodec {
    fn field_schema(&self, _: &Value, _: &str) -> Result<traffic_value::codec::FieldSchema> {
        Ok(traffic_value::codec::FieldSchema::Scalar)
    }

    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "scalar",
            version: 1,
        }
    }

    fn recognize(&self, _: &[u8], _: &Value) -> Result<Recognition> {
        Ok(Recognition::Unrecognized)
    }

    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        ensure!(
            configuration == &Value::Null,
            "scalar codec has no configuration fields"
        );
        Ok(Arc::new(Self))
    }
}

impl ValueCodec for JsonScalarCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let document = JsonCodec.decode(bytes)?;
        ensure!(
            !matches!(document.value(), Value::Array(_) | Value::Object(_)),
            "native scalar codec rejects structured payloads"
        );
        Ok(document)
    }
}

impl CodecProvider for JsonCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "json",
            version: 1,
        }
    }

    fn recognize(&self, source: &[u8], _metadata: &Value) -> Result<Recognition> {
        Ok(if parse::parse_logical(source).is_some() {
            json_recognition()
        } else {
            Recognition::Unrecognized
        })
    }

    fn recognize_source(
        &self,
        source: &[u8],
        _metadata: &Value,
    ) -> Result<(Recognition, Option<Arc<dyn ValueDocument>>)> {
        let Some(logical) = parse::parse_logical(source) else {
            return Ok((Recognition::Unrecognized, None));
        };
        Ok((json_recognition(), Some(json_document(source, logical))))
    }

    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        ensure!(
            configuration == &Value::Null,
            "JSON codec has no configuration fields"
        );
        Ok(Arc::new(Self))
    }
}

impl ValueCodec for JsonCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let logical = parse::parse_logical(bytes)
            .context("payload requires complete JSON without duplicate members")?;
        Ok(json_document(bytes, logical))
    }
}

fn json_recognition() -> Recognition {
    Recognition::Recognized {
        confidence: 100,
        configuration: Value::Null,
    }
}

fn json_document(bytes: &[u8], value: Value) -> Arc<dyn ValueDocument> {
    Arc::new(JsonDocument {
        value,
        original: bytes.to_vec(),
    })
}

struct JsonDocument {
    value: Value,
    original: Vec<u8>,
}

impl ValueDocument for JsonDocument {
    fn value(&self) -> &Value {
        &self.value
    }
    fn original_bytes(&self) -> &[u8] {
        &self.original
    }
    fn comparison_view<'a>(&'a self, _selected: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&self.value)
    }
    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>> {
        traffic_value::validate_patch(&self.value, logical, allowed)?;
        render::derived(&self.original, &serde_json::to_value(logical)?)
    }

    fn transform(&self, logical: &Value, selected: &[String]) -> Result<Vec<u8>> {
        traffic_value::transformation_paths(&self.value, logical, selected)?;
        render::transformed(&self.original, &serde_json::to_value(logical)?)
    }
}
