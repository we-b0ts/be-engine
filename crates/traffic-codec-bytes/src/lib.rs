//! Opaque bytes provide an explicitly registered exact fallback.
use anyhow::{Result, bail, ensure};
use std::{borrow::Cow, sync::Arc};
use traffic_value::{
    Value,
    codec::{CodecDescriptor, CodecProvider, Recognition, ValueCodec, ValueDocument},
};

pub struct BytesCodec;
impl CodecProvider for BytesCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "bytes",
            version: 1,
        }
    }
    fn recognize(&self, _source: &[u8], _metadata: &Value) -> Result<Recognition> {
        Ok(Recognition::Recognized {
            confidence: 0,
            configuration: Value::Null,
        })
    }
    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        ensure!(
            configuration == &Value::Null,
            "bytes codec has no configuration fields"
        );
        Ok(Arc::new(Self))
    }
}
impl ValueCodec for BytesCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "byte payload exceeds 64 MiB"
        );
        Ok(Arc::new(Document(Value::Bytes(bytes.into()))))
    }
}
struct Document(Value);
impl ValueDocument for Document {
    fn value(&self) -> &Value {
        &self.0
    }
    fn original_bytes(&self) -> &[u8] {
        let Value::Bytes(bytes) = &self.0 else {
            unreachable!("byte document retains its type")
        };
        bytes
    }
    fn comparison_view<'a>(&'a self, _selected: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&self.0)
    }
    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>> {
        traffic_value::validate_patch(&self.0, logical, allowed)?;
        let Value::Bytes(bytes) = logical else {
            bail!("byte document changed type")
        };
        ensure!(
            bytes.len() <= traffic_value::MAX_VALUE_BYTES,
            "derived bytes exceed 64 MiB"
        );
        Ok(bytes.clone())
    }
}
