//! UTF-8 string recognition and exact scalar delivery.
use anyhow::{Context, Result, ensure};
use std::{borrow::Cow, sync::Arc};
use traffic_value::{
    Value,
    codec::{CodecDescriptor, CodecProvider, Recognition, ValueCodec, ValueDocument},
};

pub struct StringCodec;
impl CodecProvider for StringCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "string",
            version: 1,
        }
    }
    fn recognize(&self, source: &[u8], _metadata: &Value) -> Result<Recognition> {
        Ok(if std::str::from_utf8(source).is_ok() {
            Recognition::Recognized {
                confidence: 10,
                configuration: Value::Null,
            }
        } else {
            Recognition::Unrecognized
        })
    }
    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        ensure!(
            configuration == &Value::Null,
            "string codec has no configuration fields"
        );
        Ok(Arc::new(Self))
    }
}
impl ValueCodec for StringCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "string payload exceeds 64 MiB"
        );
        Ok(Arc::new(Document(Value::String(
            std::str::from_utf8(bytes)
                .context("value is not UTF-8")?
                .into(),
        ))))
    }
}
struct Document(Value);
impl ValueDocument for Document {
    fn value(&self) -> &Value {
        &self.0
    }
    fn original_bytes(&self) -> &[u8] {
        self.0
            .as_str()
            .expect("string document retains its type")
            .as_bytes()
    }
    fn comparison_view<'a>(&'a self, _selected: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&self.0)
    }
    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>> {
        traffic_value::validate_patch(&self.0, logical, allowed)?;
        let bytes = logical
            .as_str()
            .context("string document changed type")?
            .as_bytes();
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "derived string exceeds 64 MiB"
        );
        Ok(bytes.into())
    }
}
