use anyhow::{Result, bail};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use traffic_contract::compare::{AnchorClocks, Comparison, RegisteredRules};
use traffic_contract::{
    codec::{Codec, CodecPlan},
    rule::{FieldContract, RuleBinding, TimeContract, ValueRule},
};
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDescriptor, PolicyInference,
    PolicyProvider, PolicyRegistry, ValuePair,
};
use traffic_policy_execution::{ExecutionContext, encoded, global};
use traffic_policy_value::{
    fields::{GlobalField, TimePolicy},
    formats::FormatHost,
};
use traffic_value::{
    Value,
    codec::{CodecDescriptor, CodecProvider, CodecRegistry, Recognition, ValueCodec},
};

struct CaseFold;
impl PolicyProvider for CaseFold {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "test.case-fold",
            version: 1,
            description: "Case-folding registration regression",
            actions: &[PolicyAction::Compare, PolicyAction::Infer],
        }
    }
    fn prepare(&self, _: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        Ok(Arc::new(Self))
    }
    fn infer(&self, source: &Value, _: &Value) -> Result<Option<PolicyInference>> {
        Ok(source.as_str().map(|_| PolicyInference {
            rule_id: "test.inferred-case-fold",
            definition: traffic_policy::PolicyDefinition::new("test.case-fold"),
            declaration: None,
        }))
    }
}
impl ComparisonPolicy for CaseFold {
    fn evaluate(&self, pair: &ValuePair<'_>, _: &mut dyn EvaluationHost) -> Result<Evaluation> {
        Ok(match (pair.source.as_str(), pair.target.as_str()) {
            (Some(source), Some(target)) if source.eq_ignore_ascii_case(target) => {
                Evaluation::matched()
            }
            _ => Evaluation::mismatch(pair, "case_fold", "case-folded values differ"),
        })
    }
}

struct Formats<'a> {
    fields: BTreeMap<String, GlobalField>,
    time: TimePolicy,
    policies: &'a PolicyRegistry,
    codecs: &'a CodecRegistry,
}
impl FormatHost for Formats<'_> {
    fn fields(&self) -> &BTreeMap<String, GlobalField> {
        &self.fields
    }
    fn time(&self) -> &TimePolicy {
        &self.time
    }
    fn policies(&self) -> &PolicyRegistry {
        self.policies
    }
    fn signing_key(&self, _: &str) -> Result<(traffic_jwt::Algorithm, &[u8])> {
        bail!("this fixture has no signing keys")
    }
    fn compare_document(
        &self,
        source: &serde_json::Value,
        target: &serde_json::Value,
        fields: &BTreeMap<String, GlobalField>,
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        let plan = Self {
            fields: fields.clone(),
            time: self.time.clone(),
            policies: self.policies,
            codecs: self.codecs,
        };
        global::compare_logical::<DeclaredRule>(
            &ExecutionContext {
                codecs: self.codecs,
                metadata: &RegisteredRules(self.policies),
            },
            source,
            target,
            &plan,
            &[],
            clocks,
        )
    }
}

struct DeclaredRule {
    id: String,
    codec: Codec,
    codec_plan: Arc<CodecPlan>,
    fields: BTreeMap<String, FieldContract>,
    delivery_time: BTreeMap<String, TimeContract>,
}
impl ValueRule for DeclaredRule {
    fn binding(&self) -> RuleBinding<'_> {
        RuleBinding {
            id: &self.id,
            codec: &self.codec,
            codec_plan: &self.codec_plan,
            fields: &self.fields,
            delivery_time: &self.delivery_time,
        }
    }
}

fn rule(id: &str, codec: serde_json::Value, pointer: &str, codecs: &CodecRegistry) -> DeclaredRule {
    let codec: Codec = serde_json::from_value(codec).unwrap();
    DeclaredRule {
        id: id.into(),
        codec_plan: Arc::new(CodecPlan::compile(&codec, codecs).unwrap()),
        codec,
        fields: BTreeMap::from([(pointer.into(), FieldContract::Exact)]),
        delivery_time: Default::default(),
    }
}

#[test]
fn an_inferred_registered_policy_respects_explicit_field_ownership() {
    let mut policies = PolicyRegistry::default();
    policies.register(Arc::new(CaseFold)).unwrap();
    let codecs = traffic_extensions::build_codecs().unwrap();
    let metadata = RegisteredRules(&policies);
    let context = ExecutionContext {
        codecs: &codecs,
        metadata: &metadata,
    };
    let plan = Formats {
        fields: Default::default(),
        time: Default::default(),
        policies: &policies,
        codecs: &codecs,
    };
    let source = br#"{"value":"Ab","strict":3}"#;
    let target = br#"{"value":"aB","strict":3}"#;
    assert!(
        global::compare::<DeclaredRule>(&context, source, target, &plan, &[], Default::default())
            .unwrap()
            .passed()
    );
    let explicit = rule("explicit", serde_json::json!("json"), "/value", &codecs);

    assert!(
        !global::compare::<DeclaredRule>(
            &context,
            source,
            target,
            &plan,
            &[&explicit],
            Default::default(),
        )
        .unwrap()
        .passed()
    );
    assert!(
        global::compare::<DeclaredRule>(
            &context,
            source,
            source,
            &plan,
            &[&explicit],
            Default::default(),
        )
        .unwrap()
        .passed()
    );
}

struct MergingCodec(Arc<AtomicUsize>);
impl CodecProvider for MergingCodec {
    fn descriptor(&self) -> CodecDescriptor {
        CodecDescriptor {
            id: "test.merge",
            version: 1,
        }
    }
    fn recognize(&self, _: &[u8], _: &Value) -> Result<Recognition> {
        Ok(Recognition::Unrecognized)
    }
    fn prepare(&self, _: &Value) -> Result<Arc<dyn ValueCodec>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        traffic_codec_string::StringCodec.prepare(&Value::Null)
    }
    fn merge(&self, configurations: &[&Value]) -> Result<Value> {
        Ok(Value::Object(BTreeMap::from([(
            "parts".into(),
            Value::Array(
                configurations
                    .iter()
                    .map(|value| (*value).clone())
                    .collect(),
            ),
        )])))
    }
}

#[test]
fn merged_plan_cache_retains_the_installed_codec_implementation() {
    let policies = PolicyRegistry::default();
    let first_calls = Arc::new(AtomicUsize::new(0));
    let mut first_registry = CodecRegistry::default();
    first_registry
        .register(Arc::new(MergingCodec(first_calls.clone())))
        .unwrap();
    let compile = |id, part| {
        rule(
            id,
            serde_json::json!({"kind":"test.merge", "part":part}),
            "",
            &first_registry,
        )
    };
    let left = compile("left", 1);
    let right = compile("right", 2);
    let rules = [&left, &right];
    let metadata = RegisteredRules(&policies);
    let context = ExecutionContext {
        codecs: &first_registry,
        metadata: &metadata,
    };
    let first = encoded::prepared_codec(&context, &rules).unwrap();
    let erased: [&dyn ValueRule; 2] = [&left, &right];
    assert!(Arc::ptr_eq(
        &first,
        &encoded::prepared_codec(&context, &erased).unwrap(),
    ));
    let shared_registry = first_registry.clone();
    let shared = encoded::prepared_codec(
        &ExecutionContext {
            codecs: &shared_registry,
            metadata: &metadata,
        },
        &rules,
    )
    .unwrap();
    assert!(Arc::ptr_eq(&first, &shared));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let mut second_registry = CodecRegistry::default();
    second_registry
        .register(Arc::new(MergingCodec(second_calls.clone())))
        .unwrap();
    let second = encoded::prepared_codec(
        &ExecutionContext {
            codecs: &second_registry,
            metadata: &metadata,
        },
        &rules,
    )
    .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(second_calls.load(Ordering::Relaxed), 1);
    assert!(Arc::ptr_eq(
        &first,
        &encoded::prepared_codec(&context, &[&right, &left]).unwrap(),
    ));
}
