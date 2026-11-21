use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use serde_json::json;
use traffic_contract::{
    codec::Codec,
    compare::{AnchorClocks, ExplicitRules, RegisteredRules},
    rule::{FieldContract, IdentityFormat},
};
use traffic_policy_value::{BindingRegistry, MessageSide, PreparedMessage, RuleBinding, ValueRule};
use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};
use traffic_value::{
    Value,
    codec::{
        CodecDescriptor, CodecProvider, CodecRegistry, Recognition, ValueCodec, ValueDocument,
    },
};

struct PrefixCodec;

impl CodecProvider for PrefixCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "fixture-prefix",
            version: 1,
        }
    }

    fn recognize(&self, source: &[u8], _: &Value) -> Result<Recognition> {
        Ok(if source.starts_with(b"fixture=") {
            Recognition::Recognized {
                confidence: 100,
                configuration: Value::Null,
            }
        } else {
            Recognition::Unrecognized
        })
    }

    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        ensure!(configuration == &Value::Null, "fixture has no options");
        Ok(Arc::new(Self))
    }
}

impl ValueCodec for PrefixCodec {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn ValueDocument>> {
        let value = std::str::from_utf8(bytes)?
            .strip_prefix("fixture=")
            .context("missing fixture prefix")?;
        Ok(Arc::new(Document {
            original: bytes.into(),
            value: Value::String(value.into()),
        }))
    }
}

struct Document {
    original: Vec<u8>,
    value: Value,
}

impl ValueDocument for Document {
    fn value(&self) -> &Value {
        &self.value
    }
    fn original_bytes(&self) -> &[u8] {
        &self.original
    }
    fn comparison_view<'a>(&'a self, _: &[String]) -> Cow<'a, Value> {
        Cow::Borrowed(&self.value)
    }
    fn encode(&self, logical: &Value, allowed: &[String]) -> Result<Vec<u8>> {
        traffic_value::validate_patch(&self.value, logical, allowed)?;
        Ok(format!(
            "fixture={}",
            logical.as_str().context("fixture value requires text")?
        )
        .into_bytes())
    }
}

struct Message(&'static str, &'static str);

impl ProtocolMessage for Message {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"frame":"fixture"}),
            values: BTreeMap::from([
                (
                    "selected".into(),
                    ProjectedValue::bytes(Bytes::from_static(self.0.as_bytes())),
                ),
                (
                    "unselected".into(),
                    ProjectedValue::bytes(Bytes::from_static(self.1.as_bytes())),
                ),
            ]),
        })
    }
    fn locate(&self, selector: &serde_json::Value) -> Result<Vec<String>> {
        Ok(vec![
            selector
                .as_str()
                .context("fixture location requires text")?
                .into(),
        ])
    }
    fn evidence(&self, _: &serde_json::Value) -> Result<serde_json::Value> {
        Ok(json!({}))
    }
}

#[test]
fn injected_codec_reaches_binding_comparison_and_delivery_without_framework_registration() {
    let binding = RuleBinding {
        rule: Arc::new(ValueRule {
            id: "entity".into(),
            contract: FieldContract::Identity {
                prefix: "id_".into(),
                format: IdentityFormat::Decimal,
            },
        }),
        selector: json!("selected"),
        codec: Codec::registered("fixture-prefix", serde_json::Value::Null).unwrap(),
        pointer: String::new(),
    };
    let mut missing = BindingRegistry::default();
    let before = missing.signature().unwrap();
    assert!(
        missing
            .register("fixture", MessageSide::Request, binding.clone(), false)
            .is_err()
    );
    assert_eq!(missing.signature().unwrap(), before);

    let mut codecs = CodecRegistry::default();
    codecs.register(Arc::new(PrefixCodec)).unwrap();
    let mut bindings = BindingRegistry::new(codecs.clone());
    bindings
        .register("fixture", MessageSide::Request, binding, false)
        .unwrap();
    let rules = bindings.for_protocol("fixture");
    let source = Message("fixture=id_42", "strict");
    let prepared = PreparedMessage::compile(&source, &rules.request, &codecs).unwrap();
    let policies = RegisteredRules(traffic_extensions::policies());
    let comparison = prepared
        .compare(
            &Message("fixture=id_1042", "strict"),
            AnchorClocks::default(),
            &policies,
        )
        .unwrap();
    assert!(comparison.passed());
    assert!(comparison.evaluated.contains("entity"));
    assert!(
        !prepared
            .compare(
                &Message("fixture=id_1042", "changed"),
                AnchorClocks::default(),
                &policies
            )
            .unwrap()
            .passed()
    );
    assert!(
        !prepared
            .compare(
                &Message("id_1042", "strict"),
                AnchorClocks::default(),
                &policies
            )
            .unwrap()
            .passed()
    );

    let rendered = prepared
        .render_values(
            &BTreeMap::from([("selected".into(), json!("id_1042"))]),
            AnchorClocks::default(),
            &policies,
        )
        .unwrap();
    assert_eq!(rendered["selected"], "fixture=id_1042");
    assert_eq!(rendered["unselected"], "strict");
    assert!(
        !prepared
            .compare(
                &Message("fixture=id_1042", "strict"),
                AnchorClocks::default(),
                &ExplicitRules
            )
            .unwrap()
            .passed()
    );
}

#[test]
fn scalar_formats_delegate_source_decoding_and_delivery_to_a_registered_codec() {
    use traffic_policy_value::{
        ExecutionContext,
        fields::{GlobalField, GlobalIdentityFormat, TimePolicy},
        scalar,
    };
    let mut codecs = CodecRegistry::default();
    codecs.register(Arc::new(PrefixCodec)).unwrap();
    let metadata = RegisteredRules(traffic_extensions::policies());
    let context = ExecutionContext {
        codecs: &codecs,
        metadata: &metadata,
    };
    let field = GlobalField::Identity {
        formats: vec![GlobalIdentityFormat {
            prefix: "id_".into(),
            format: IdentityFormat::Decimal,
        }],
    };
    let source = scalar::decode_field(b"fixture=id_42", &field, &context)
        .unwrap()
        .unwrap();
    assert_eq!(source.logical, json!("id_42"));
    assert!(!source.is_literal_text());
    assert_eq!(
        source.encode(&json!("id_1042")).unwrap(),
        b"fixture=id_1042"
    );
    assert_eq!(
        source.decoder().decode(b"fixture=id_1042").unwrap(),
        json!("id_1042")
    );
    assert!(source.target(b"id_1042").is_err());

    let comparison = scalar::compare(
        &context,
        "native-field",
        b"fixture=id_42",
        b"fixture=id_1042",
        &field,
        &TimePolicy::default(),
        AnchorClocks::default(),
        &[],
    )
    .unwrap();
    assert!(comparison.passed());
    assert!(comparison.evaluated.contains("native-field"));
}

#[test]
fn scalar_codec_rendering_retains_original_tokens_and_numeric_identity_interpretation() {
    use traffic_policy_value::{
        ExecutionContext,
        fields::{GlobalField, GlobalIdentityFormat},
        scalar,
    };
    assert!(
        scalar::decode(b"plain text", &CodecRegistry::default())
            .unwrap()
            .is_none()
    );
    let codecs = traffic_extensions::codecs();
    let source = scalar::decode(b"  \"\\u0061\" \n", codecs)
        .unwrap()
        .unwrap();
    assert_eq!(source.logical, json!("a"));
    assert_eq!(source.encode(&json!("a")).unwrap(), b"  \"\\u0061\" \n");
    assert_eq!(source.encode(&json!("b")).unwrap(), b"  \"b\" \n");
    assert!(source.target(br#"{"changed":"structure"}"#).is_err());
    assert!(
        scalar::decode(br#"{"object":1}"#, codecs)
            .unwrap()
            .is_none()
    );

    let metadata = RegisteredRules(traffic_extensions::policies());
    let context = ExecutionContext {
        codecs,
        metadata: &metadata,
    };
    let field = GlobalField::Identity {
        formats: vec![GlobalIdentityFormat {
            prefix: String::new(),
            format: IdentityFormat::Hex(8),
        }],
    };
    let source = scalar::decode_field(b"12345678", &field, &context)
        .unwrap()
        .unwrap();
    assert!(source.is_literal_text());
    assert_eq!(source.logical, json!("12345678"));
    assert_eq!(source.encode(&json!("abcdef01")).unwrap(), b"abcdef01");
}
