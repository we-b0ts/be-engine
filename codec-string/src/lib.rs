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
        if configuration == &Value::Null {
            return Ok(Arc::new(Self));
        }
        let fields = configuration
            .as_object()
            .context("string affixes must be an object")?;
        ensure!(
            fields.len() == 2,
            "string affixes require prefix and suffix"
        );
        let prefix = fields
            .get("prefix")
            .and_then(Value::as_str)
            .context("string prefix must be text")?;
        let suffix = fields
            .get("suffix")
            .and_then(Value::as_str)
            .context("string suffix must be text")?;
        ensure!(
            prefix.len() + suffix.len() <= 1024,
            "string affixes exceed 1024 bytes"
        );
        Ok(Arc::new(Affixes {
            prefix: prefix.into(),
            suffix: suffix.into(),
        }))
    }
}
impl ValueCodec for StringCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        Ok(Arc::new(Document {
            value: Value::String(text(bytes)?.into()),
            frame: None,
        }))
    }
}

struct Affixes {
    prefix: String,
    suffix: String,
}

impl ValueCodec for Affixes {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let value = text(bytes)?
            .strip_prefix(&self.prefix)
            .and_then(|value| value.strip_suffix(&self.suffix))
            .context("value violates its fixed string affixes")?;
        Ok(Arc::new(Document {
            value: Value::String(value.into()),
            frame: Some(Frame {
                bytes: bytes.into(),
                start: self.prefix.len(),
                end: bytes.len() - self.suffix.len(),
            }),
        }))
    }
}

fn text(bytes: &[u8]) -> Result<&str> {
    ensure!(
        bytes.len() <= traffic_value::MAX_VALUE_BYTES,
        "string payload exceeds 64 MiB"
    );
    std::str::from_utf8(bytes).context("value is not UTF-8")
}

struct Frame {
    bytes: Vec<u8>,
    start: usize,
    end: usize,
}

struct Document {
    value: Value,
    frame: Option<Frame>,
}

impl ValueDocument for Document {
    fn value(&self) -> &Value {
        &self.value
    }
    fn original_bytes(&self) -> &[u8] {
        match &self.frame {
            Some(frame) => &frame.bytes,
            None => self
                .value
                .as_str()
                .expect("string document retains its type")
                .as_bytes(),
        }
    }
    fn comparison_view<'a>(&'a self, _selected: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&self.value)
    }
    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>> {
        traffic_value::validate_patch(&self.value, logical, allowed)?;
        let bytes = logical
            .as_str()
            .context("string document changed type")?
            .as_bytes();
        let (prefix, suffix) = self.frame.as_ref().map_or((&[][..], &[][..]), |frame| {
            (&frame.bytes[..frame.start], &frame.bytes[frame.end..])
        });
        ensure!(
            prefix.len() + bytes.len() + suffix.len() <= traffic_value::MAX_VALUE_BYTES,
            "derived string exceeds 64 MiB"
        );
        Ok([prefix, bytes, suffix].concat())
    }
}
