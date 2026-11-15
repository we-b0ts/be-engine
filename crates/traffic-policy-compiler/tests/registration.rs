use anyhow::{Result, ensure};
use std::sync::Arc;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDefinition, PolicyDescriptor,
    PolicyProvider, PolicyRegistry, ValuePair,
};
use traffic_policy_compiler::{CompilationContext, FieldContract, Rule, compiler};
use traffic_value::{
    Value,
    codec::{
        CodecDescriptor, CodecProvider, CodecRegistry, FieldSchema, Recognition, ValueCodec,
        ValueType,
    },
};

struct Custom;

impl PolicyProvider for Custom {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "test.custom",
            version: 1,
            description: "Compilation registration regression",
            actions: &[PolicyAction::Compare],
        }
    }

    fn prepare(&self, _: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        Ok(Arc::new(Self))
    }
}

impl ComparisonPolicy for Custom {
    fn validate_schema(&self, schema: &FieldSchema) -> Result<()> {
        ensure!(
            matches!(
                schema,
                FieldSchema::Dynamic | FieldSchema::Typed(ValueType::String)
            ),
            "custom policy requires a string value"
        );
        Ok(())
    }

    fn evaluate(&self, _: &ValuePair<'_>, _: &mut dyn EvaluationHost) -> Result<Evaluation> {
        Ok(Evaluation::matched())
    }
}

struct TypedCodec(ValueType);

impl CodecProvider for TypedCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "test.codec",
            version: 1,
        }
    }
    fn recognize(&self, _: &[u8], _: &Value) -> Result<Recognition> {
        Ok(Recognition::Unrecognized)
    }
    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ValueCodec>> {
        traffic_codec_string::StringCodec.prepare(configuration)
    }
    fn field_schema(&self, _: &Value, _: &str) -> Result<FieldSchema> {
        Ok(FieldSchema::Typed(self.0))
    }
}

#[test]
fn compilation_uses_only_its_supplied_registries() {
    let mut policies = PolicyRegistry::default();
    policies.register(Arc::new(Custom)).unwrap();
    let mut codecs = CodecRegistry::default();
    codecs
        .register(Arc::new(traffic_codec_string::StringCodec))
        .unwrap();
    let mut rule: Rule = serde_json::from_value(serde_json::json!({
        "id":"custom", "surface":"api.response", "match":{"api":"GET /value"},
        "slot":"body", "codec":{"kind":"string"},
        "contract":{"":{"kind":"exact"}},
        "proof":{"source":"source.rs:1", "fact":"The application uses this custom value contract"}
    }))
    .unwrap();
    rule.contract.insert(
        String::new(),
        FieldContract::Policy(PolicyDefinition::new("test.custom")),
    );
    let context = CompilationContext {
        policies: &policies,
        codecs: &codecs,
    };
    let prepared = compiler::compile_rule(&rule, &context).unwrap();
    assert_eq!(
        prepared.codec_plan.decode(b"value").unwrap().logical,
        serde_json::json!("value")
    );
    assert!(
        compiler::compile_rule(
            &rule,
            &CompilationContext {
                policies: &PolicyRegistry::default(),
                codecs: &codecs,
            }
        )
        .is_err()
    );
    assert!(
        compiler::compile_rule(
            &rule,
            &CompilationContext {
                policies: &policies,
                codecs: &CodecRegistry::default(),
            }
        )
        .is_err()
    );
    rule.codec =
        traffic_policy_compiler::Codec::registered("test.codec", serde_json::Value::Null).unwrap();
    for (shape, accepted) in [(ValueType::String, true), (ValueType::Number, false)] {
        let mut codecs = CodecRegistry::default();
        codecs.register(Arc::new(TypedCodec(shape))).unwrap();
        assert_eq!(
            compiler::compile_rule(
                &rule,
                &CompilationContext {
                    policies: &policies,
                    codecs: &codecs,
                }
            )
            .is_ok(),
            accepted
        );
    }
}
