//! Extension conformance runs through the format-independent registry.
use std::{borrow::Cow, sync::Arc};

use anyhow::{Context, Result, ensure};
use traffic_value::{
    Value,
    codec::{
        CodecDescriptor, CodecProvider, CodecRegistry, Recognition, ValueCodec, ValueDocument,
    },
};

fn registry() -> CodecRegistry {
    let mut registry = CodecRegistry::default();
    registry
        .register(Arc::new(traffic_codec_json::JsonCodec))
        .unwrap();
    registry
        .register(Arc::new(traffic_codec_protobuf::ProtobufProvider))
        .unwrap();
    registry
        .register(Arc::new(traffic_codec_string::StringCodec))
        .unwrap();
    registry
        .register(Arc::new(traffic_codec_bytes::BytesCodec))
        .unwrap();
    registry
}

#[test]
fn auto_selection_is_source_bound_and_keeps_independent_candidate_diagnostics() {
    let registry = registry();
    for (bytes, expected) in [
        (b"{\"items\":[1,2]}".as_slice(), "json"),
        (b"ordinary text".as_slice(), "string"),
        ([0xff, 0xfe].as_slice(), "bytes"),
    ] {
        let selected = registry.recognize(bytes, &Value::Null).unwrap();
        assert_eq!(selected.descriptor().id, expected);
        let document = selected.decode(bytes).unwrap();
        assert_eq!(document.encode(document.value(), &[]).unwrap(), bytes);
    }
    let selected = registry.recognize(b"{\"id\":1}", &Value::Null).unwrap();
    assert!(selected.decode(b"broken target JSON").is_err());
    let probes = registry.inspect(b"ordinary text", &Value::Null).unwrap();
    assert!(probes.iter().any(|probe| {
        probe.descriptor.id == "protobuf"
            && matches!(&probe.recognition, Recognition::Candidate { reason } if reason.contains("field bindings"))
    }));
}

#[test]
fn registered_json_keeps_original_tokens_and_enforces_selected_edit_paths() {
    let prepared = registry().prepare("json", &Value::Null).unwrap();
    let original = b" {\"time\": 1.00, \"value\":\"old\"}\n";
    let document = prepared.decode(original).unwrap();
    let mut logical = document.value().clone();
    let Value::Object(fields) = &mut logical else {
        panic!("object document")
    };
    fields.insert("value".into(), Value::String("new".into()));
    assert!(document.encode(&logical, &[]).is_err());
    assert_eq!(
        document.encode(&logical, &["/value".into()]).unwrap(),
        b" {\"time\": 1.00, \"value\":\"new\"}\n"
    );
    assert!(prepared.decode(b"{\"id\":1,\"id\":2}").is_err());
    assert!(prepared.decode(b"{\"id\":9007199254740993.0}").is_err());
}

#[test]
fn native_scalar_validation_is_installed_with_its_provider() {
    let mut registry = registry();
    assert!(registry.prepare("scalar", &Value::Null).is_err());
    registry
        .register(Arc::new(traffic_codec_json::JsonScalarCodec))
        .unwrap();
    let scalar = registry.prepare("scalar", &Value::Null).unwrap();
    assert_eq!(
        scalar.decode(b"12").unwrap().value(),
        &serde_json::from_value(serde_json::json!(12)).unwrap()
    );
    assert_ne!(
        scalar.decode(b"12").unwrap().value(),
        scalar.decode(br#""12""#).unwrap().value()
    );
    assert!(scalar.decode(b"null").is_ok());
    assert!(scalar.decode(b"{}").is_err());
    assert!(scalar.decode(b"[]").is_err());
    assert_eq!(
        registry
            .recognize(b"12", &Value::Null)
            .unwrap()
            .descriptor()
            .id,
        "json"
    );
}

#[test]
fn typed_codec_owns_alias_overlap_and_reserved_field_validation() {
    let registry = registry();
    let configuration = |alias: &str, field: u32| -> Value {
        serde_json::from_value(serde_json::json!({"fields":{
            alias:{"field_path":[field],"field_type":"uint64","repeated":true}
        }}))
        .unwrap()
    };
    let left = configuration("/left", 1);
    let right = configuration("/right", 1);
    let other = configuration("/other", 2);
    assert!(
        registry
            .fields_overlap("protobuf", &left, "/left", &right, "/right")
            .unwrap()
    );
    assert!(
        registry
            .fields_overlap("protobuf", &left, "/left/*", &right, "/right/0")
            .unwrap()
    );
    assert!(
        registry
            .fields_overlap("protobuf", &left, "/left/0", &right, "/right/0")
            .unwrap()
    );
    assert!(
        !registry
            .fields_overlap("protobuf", &left, "/left/0", &right, "/right/1")
            .unwrap()
    );
    assert!(
        !registry
            .fields_overlap("protobuf", &left, "/left", &other, "/other")
            .unwrap()
    );
    assert!(
        registry
            .fields_overlap("protobuf", &left, "/left/00", &right, "/right/0")
            .is_err()
    );
    for field in [0, 19_000, 19_999, 1 << 29] {
        assert!(
            registry
                .prepare("protobuf", &configuration("/value", field))
                .is_err()
        );
    }
}

#[test]
fn registered_protobuf_preserves_unselected_wire_and_owns_its_remainder() {
    let configuration: Value = serde_json::from_value(serde_json::json!({
        "fields": {"/id": {"field_path":[1], "field_type":"uint64"}}
    }))
    .unwrap();
    let metadata = Value::Object(std::collections::BTreeMap::from([(
        "protobuf".into(),
        configuration.clone(),
    )]));
    let prepared = registry()
        .recognize(&[8, 0x81, 0, 16, 2], &metadata)
        .unwrap();
    assert_eq!(prepared.descriptor().id, "protobuf");
    let source = prepared.decode(&[8, 0x81, 0, 16, 2]).unwrap();
    let canonical = prepared.decode(&[8, 1, 16, 2]).unwrap();
    assert_ne!(source.comparison_view(&[]), canonical.comparison_view(&[]));
    assert_eq!(
        source.comparison_view(&["/id".into()]),
        canonical.comparison_view(&["/id".into()])
    );
    assert_eq!(
        source.encode(source.value(), &[]).unwrap(),
        [8, 0x81, 0, 16, 2]
    );
    let mut changed = source.value().clone();
    let Value::Object(fields) = &mut changed else {
        panic!("message document")
    };
    fields.insert(
        "id".into(),
        serde_json::from_value(serde_json::json!(128)).unwrap(),
    );
    assert_eq!(
        source.encode(&changed, &["/id".into()]).unwrap(),
        [8, 0x80, 1, 16, 2]
    );
    let Value::Object(fields) = &mut changed else {
        panic!("message document")
    };
    fields.insert(traffic_codec_protobuf::REMAINDER_KEY.into(), Value::Null);
    assert!(source.encode(&changed, &["".into()]).is_err());
    assert!(registry().prepare("protobuf", &Value::Null).is_err());
}

struct PrefixCodec;
impl CodecProvider for PrefixCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "fixture-prefix",
            version: 1,
        }
    }
    fn recognize(&self, source: &[u8], _metadata: &Value) -> Result<Recognition> {
        Ok(if source.starts_with(b"fixture=") {
            Recognition::Recognized {
                confidence: 300,
                configuration: Value::Null,
            }
        } else {
            Recognition::Unrecognized
        })
    }
    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        ensure!(
            configuration == &Value::Null,
            "fixture codec has no configuration"
        );
        Ok(Arc::new(Self))
    }
}
impl ValueCodec for PrefixCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let text = std::str::from_utf8(bytes)?
            .strip_prefix("fixture=")
            .context("fixture prefix changed")?;
        Ok(Arc::new(PrefixDocument {
            original: bytes.into(),
            value: Value::String(text.into()),
        }))
    }
}
struct PrefixDocument {
    original: Vec<u8>,
    value: Value,
}
impl ValueDocument for PrefixDocument {
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
        Ok(format!(
            "fixture={}",
            logical.as_str().context("fixture string changed type")?
        )
        .into_bytes())
    }
}

#[test]
fn a_new_codec_enters_and_leaves_through_registration_only() {
    let mut registry = registry();
    assert!(registry.prepare("fixture-prefix", &Value::Null).is_err());
    registry.register(Arc::new(PrefixCodec)).unwrap();
    let prepared = registry.recognize(b"fixture=old", &Value::Null).unwrap();
    assert_eq!(prepared.descriptor().id, "fixture-prefix");
    let source = prepared.decode(b"fixture=old").unwrap();
    assert_eq!(source.value(), &Value::String("old".into()));
    assert_eq!(
        source
            .encode(&Value::String("new".into()), &["".into()])
            .unwrap(),
        b"fixture=new"
    );
    assert!(registry.register(Arc::new(PrefixCodec)).is_err());
    assert_eq!(registry.descriptors().count(), 5);
    let empty = CodecRegistry::default();
    assert!(empty.prepare("fixture-prefix", &Value::Null).is_err());
}
