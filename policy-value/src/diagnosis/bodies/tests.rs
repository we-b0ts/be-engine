use super::*;
use anyhow::ensure;
use std::{borrow::Cow, collections::BTreeMap};
use traffic_value::{
    Value as Logical,
    codec::{CodecDescriptor, CodecProvider, Recognition, ValueCodec},
};

struct NativeCodec(&'static str);

impl CodecProvider for NativeCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: self.0,
            version: 1,
        }
    }

    fn recognize(&self, source: &[u8], _: &Logical) -> Result<Recognition> {
        Ok(if source.starts_with(b"native:") {
            Recognition::Recognized {
                confidence: 100,
                configuration: Logical::Null,
            }
        } else {
            Recognition::Unrecognized
        })
    }

    fn prepare(&self, options: &Logical) -> Result<Arc<dyn ValueCodec>> {
        ensure!(options == &Logical::Null, "native codec has no options");
        Ok(Arc::new(Self(self.0)))
    }
}

impl ValueCodec for NativeCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let payload = bytes
            .strip_prefix(b"native:")
            .context("missing native envelope")?;
        Ok(Arc::new(Document {
            bytes: bytes.into(),
            value: Logical::Object(BTreeMap::from([(
                "payload".into(),
                Logical::Bytes(payload.into()),
            )])),
        }))
    }
}

struct Document {
    bytes: Vec<u8>,
    value: Logical,
}

impl ValueDocument for Document {
    fn value(&self) -> &Logical {
        &self.value
    }
    fn original_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn comparison_view<'a>(&'a self, _: &[String]) -> Cow<'a, Logical> {
        Cow::Borrowed(&self.value)
    }
    fn encode(&self, _: &Logical, _: &[String]) -> Result<Vec<u8>> {
        anyhow::bail!("diagnostic fixture is read-only")
    }
}

fn registry() -> CodecRegistry {
    let mut registry = CodecRegistry::default();
    registry
        .register(Arc::new(NativeCodec("custom-native")))
        .unwrap();
    registry
}

#[test]
fn registration_supplies_body_recognition_and_typed_field_differences() {
    let codecs = registry();
    let result = differences(&codecs, b"native:\xff\x01", b"native:\xff\x02", 0);
    assert_eq!(result["codec"], "custom-native");
    assert_eq!(result["analysis_complete"], true);
    assert_eq!(result["total_differences"], 1);
    assert_eq!(result["differences"][0]["pointer"], "/payload");
    assert_eq!(result["differences"][0]["source"]["type"], "bytes");
    assert_eq!(result["differences"][0]["bytes"]["first_different_byte"], 1);
    assert_eq!(
        differences(&codecs, b"native:a", b"native:b", 20)["returned_differences"],
        0
    );

    let selected = at_pointer(&codecs, b"native:a", b"native:b", "/payload");
    assert_eq!(selected["source"]["type"], "bytes");
    assert_eq!(selected["bytes"]["first_different_byte"], 0);
}

#[test]
fn target_must_decode_with_the_source_selected_codec() {
    let result = differences(&registry(), b"native:source", b"other:target", 0);
    assert_eq!(result["presence"], "unavailable");
    assert_eq!(result["analysis_complete"], false);
}

#[test]
fn missing_and_ambiguous_installations_keep_their_distinct_outcomes() {
    let empty = CodecRegistry::default();
    let raw = differences(&empty, b"source", b"target", 0);
    assert_eq!(raw["codec"], "bytes");
    assert_eq!(raw["total_differences"], 1);
    assert_eq!(
        at_pointer(&empty, b"source", b"target", "/payload")["presence"],
        "unavailable"
    );

    let mut ambiguous = registry();
    ambiguous
        .register(Arc::new(NativeCodec("another-native")))
        .unwrap();
    let result = differences(&ambiguous, b"native:a", b"native:b", 0);
    assert_eq!(result["analysis_complete"], false);
    assert!(result["reason"].as_str().unwrap().contains("ambiguous"));
}
