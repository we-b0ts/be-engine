use super::*;
use serde_json::json;
use traffic_contract::{
    compare::ExplicitRules,
    identity::{IdentityDecision, IdentityPair, IdentityStore, PreparedIdentityDelivery},
    rule::{ClockScope, IdentityFormat, TimeAnchor, TimeRelation, TimestampFormat},
    time::ClockPair,
};
mod typed;

struct RawDocument(&'static [u8]);
impl ProtocolMessage for RawDocument {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"shape":"raw"}),
            values: BTreeMap::from([("value".into(), ProjectedValue::bytes(self.0))]),
        })
    }
    fn locate(&self, _: &Value) -> Result<Vec<String>> {
        Ok(vec!["value".into()])
    }
    fn evidence(&self, _: &Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

struct CaseDocumentPolicy(traffic_policy::PolicyRegistry);
impl DocumentPolicy for CaseDocumentPolicy {
    fn paths(&self, source: &traffic_value::Value) -> Result<Vec<String>> {
        Ok(if source.as_str().is_some() {
            vec![String::new()]
        } else {
            Vec::new()
        })
    }
    fn compare(
        &self,
        source: &traffic_value::Value,
        target: &traffic_value::Value,
        _: &[Field<'_>],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        let contract = FieldContract::Policy(traffic_policy::PolicyDefinition {
            id: "fixture-case".into(),
            version: 3,
            options: json!({"enabled":true}),
        });
        Ok(compare::compare_logical_all(
            source,
            target,
            &[Field {
                rule_id: "case",
                pointer: "",
                contract: &contract,
            }],
            &[],
            &[],
            clocks,
            &[],
            &traffic_contract::compare::RegisteredRules(&self.0),
        ))
    }
}

#[test]
fn automatic_codec_selection_is_pinned_to_source_for_normal_message_comparison() {
    let mut registry = traffic_policy::PolicyRegistry::default();
    registry.register(Arc::new(CasePolicy)).unwrap();
    let policy: Arc<dyn DocumentPolicy> = Arc::new(CaseDocumentPolicy(registry));
    let prepare = |source: &RawDocument, codecs: &CodecRegistry| {
        PreparedMessage::compile_with_policy(source, &[], Some(policy.clone()), codecs).unwrap()
    };
    let compare = |source: &PreparedMessage, target: &'static [u8]| {
        source
            .compare(
                &RawDocument(target),
                AnchorClocks::default(),
                &ExplicitRules,
            )
            .unwrap()
            .passed()
    };
    let json = prepare(&RawDocument(br#""ALPHA""#), traffic_extensions::codecs());
    assert!(compare(&json, br#""alpha""#));
    assert!(!compare(&json, b"alpha"));
    let text = prepare(&RawDocument(b"ALPHA"), traffic_extensions::codecs());
    assert!(compare(&text, b"alpha"));
    assert!(!compare(&text, br#""alpha""#));
    let removed = prepare(&RawDocument(b"ALPHA"), &CodecRegistry::default());
    assert!(compare(&removed, b"ALPHA"));
    assert!(!compare(&removed, b"alpha"));
    let opaque = prepare(&RawDocument(b"\xff"), traffic_extensions::codecs());
    assert!(compare(&opaque, b"\xff"));
    assert!(!compare(&opaque, b"\xfe"));
}

struct CasePolicy;

impl traffic_policy::PolicyProvider for CasePolicy {
    fn descriptor(&self) -> traffic_policy::PolicyDescriptor {
        traffic_policy::PolicyDescriptor {
            id: "fixture-case",
            version: 3,
            description: "Compare selected text without letter case",
            actions: &[traffic_policy::PolicyAction::Compare],
        }
    }
    fn prepare(
        &self,
        configuration: &traffic_value::Value,
    ) -> Result<Arc<dyn traffic_policy::ComparisonPolicy>> {
        ensure!(
            configuration.pointer("/enabled") == Some(&traffic_value::Value::Bool(true)),
            "fixture option is required"
        );
        Ok(Arc::new(Self))
    }
}

impl traffic_policy::ComparisonPolicy for CasePolicy {
    fn applies(&self, source: &traffic_value::Value, _: &traffic_value::Value) -> Result<bool> {
        Ok(source.as_str().is_some())
    }
    fn evaluate(
        &self,
        pair: &traffic_policy::ValuePair<'_>,
        _: &mut dyn traffic_policy::EvaluationHost,
    ) -> Result<traffic_policy::Evaluation> {
        Ok(match pair.source.as_str().zip(pair.target.as_str()) {
            Some((source, target)) if source.eq_ignore_ascii_case(target) => {
                traffic_policy::Evaluation::matched()
            }
            _ => {
                traffic_policy::Evaluation::mismatch(pair, "case_changed", "selected text differs")
            }
        })
    }
}

#[test]
fn a_new_policy_uses_the_open_definition_and_injected_runtime_registry() {
    let definition: traffic_policy::PolicyDefinition = serde_json::from_value(json!({
        "id":"fixture-case","version":3,"options":{"enabled":true}
    }))
    .unwrap();
    let contract: FieldContract = serde_json::from_value(json!({
        "kind":"policy","id":"fixture-case","version":3,"options":{"enabled":true}
    }))
    .unwrap();
    let source = Document(BTreeMap::from([(
        "first".into(),
        json!({"name":"ALPHA","stable":7}),
    )]));
    let bindings = [binding(
        Arc::new(ValueRule {
            id: "case".into(),
            contract,
        }),
        "first",
        "/name",
    )];
    let prepared = prepare(&source, &bindings).unwrap();
    let mut registry = traffic_policy::PolicyRegistry::default();
    registry.register(Arc::new(CasePolicy)).unwrap();
    let policy = registry.prepare_definition(&definition).unwrap();
    assert!(
        policy
            .applies(
                &traffic_value::Value::String("ALPHA".into()),
                &traffic_value::Value::Null
            )
            .unwrap()
    );
    assert!(
        !policy
            .applies(&traffic_value::Value::Null, &traffic_value::Value::Null)
            .unwrap()
    );
    let metadata = traffic_contract::compare::RegisteredRules(&registry);
    let target = Document(BTreeMap::from([(
        "first".into(),
        json!({"name":"alpha","stable":7}),
    )]));
    assert!(
        prepared
            .compare(&target, AnchorClocks::default(), &metadata)
            .unwrap()
            .passed()
    );
    assert!(
        !prepared
            .compare(&target, AnchorClocks::default(), &ExplicitRules)
            .unwrap()
            .passed()
    );
    let changed = Document(BTreeMap::from([(
        "first".into(),
        json!({"name":"alpha","stable":8}),
    )]));
    assert!(
        !prepared
            .compare(&changed, AnchorClocks::default(), &metadata)
            .unwrap()
            .passed()
    );
    for (version, options) in [(1, json!({"enabled":true})), (3, json!({}))] {
        let definition = traffic_policy::PolicyDefinition {
            version,
            options,
            ..definition.clone()
        };
        assert!(registry.prepare_definition(&definition).is_err());
    }
}

fn prepare(native: &dyn ProtocolMessage, bindings: &[RuleBinding]) -> Result<PreparedMessage> {
    PreparedMessage::compile(native, bindings, traffic_extensions::codecs())
}

pub(crate) struct Document(pub BTreeMap<String, Value>);
impl ProtocolMessage for Document {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"frame":"document"}),
            values: self
                .0
                .iter()
                .map(|(name, value)| {
                    Ok((
                        name.clone(),
                        ProjectedValue::json(serde_json::to_vec(value)?),
                    ))
                })
                .collect::<Result<_>>()?,
        })
    }
    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        Ok(vec![
            selector
                .as_str()
                .context("document selector requires a value name")?
                .into(),
        ])
    }
    fn evidence(&self, _: &Value) -> Result<Value> {
        Ok(json!({"fields":self.0.keys().collect::<Vec<_>>()}))
    }
}
impl traffic_protocol::message::MessageEncoder for Document {
    fn encode(&self, values: &BTreeMap<String, bytes::Bytes>) -> Result<bytes::Bytes> {
        Ok(bytes::Bytes::from(serde_json::to_vec(
            &values
                .iter()
                .map(|(name, bytes)| Ok((name.clone(), serde_json::from_slice::<Value>(bytes)?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
        )?))
    }
}

fn binding(rule: Arc<ValueRule>, location: &str, pointer: &str) -> RuleBinding {
    RuleBinding {
        rule,
        selector: json!(location),
        codec: Codec::Json,
        pointer: pointer.into(),
    }
}

fn source() -> (Document, PreparedMessage) {
    let source = Document(BTreeMap::from([
        (
            "first".into(),
            json!({"id":42,"when":12_000_001,"stable":[2,1,2]}),
        ),
        ("second".into(), json!({"id":42})),
    ]));
    let identity = Arc::new(ValueRule {
        id: "entity".into(),
        contract: FieldContract::Identity {
            prefix: String::new(),
            format: IdentityFormat::Decimal,
        },
    });
    let clock = Arc::new(ValueRule {
        id: "clock".into(),
        contract: FieldContract::Time {
            format: TimestampFormat::UnixMicroseconds,
            relation: TimeRelation::PreserveOffset,
            anchor: TimeAnchor::Observation,
            utc_offset: None,
            clock_group: None,
            clock_scope: ClockScope::default(),
        },
    });
    let prepared = prepare(
        &source,
        &[
            binding(identity.clone(), "first", "/id"),
            binding(identity, "second", "/id"),
            binding(clock, "first", "/when"),
        ],
    )
    .unwrap();
    (source, prepared)
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        observation: Some(ClockPair {
            source: Some("1970-01-01T00:00:10Z".parse().unwrap()),
            target: Some("1970-01-01T00:01:50Z".parse().unwrap()),
        }),
        ..Default::default()
    }
}

#[test]
fn identity_and_time_delivery_share_one_strict_frame_and_keep_native_remainders() {
    let (_, prepared) = source();
    let mut identities = IdentityStore::default();
    identities
        .commit(
            IdentityDecision::prepare(
                "case",
                vec![IdentityPair {
                    source: "42".into(),
                    target: "1042".into(),
                }],
            )
            .unwrap(),
        )
        .unwrap();
    let rendered = prepared
        .render_delivery(
            clocks(),
            &traffic_contract::compare::RegisteredRules(traffic_extensions::policies()),
            &std::collections::BTreeSet::from(["clock".into()]),
            |selected| {
                let selected = selected
                    .iter()
                    .copied()
                    .map(PreparedIdentityDelivery::prepare)
                    .collect::<Result<Vec<_>>>()?;
                identities
                    .deliveries("case", &selected)
                    .map(|(values, _)| values)
            },
        )
        .unwrap();
    let first: Value = serde_json::from_slice(&rendered.values["first"]).unwrap();
    assert_eq!(
        first,
        json!({"id":1042,"when":112_000_001,"stable":[2,1,2]})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&rendered.values["second"]).unwrap(),
        json!({"id":1042})
    );
    assert!(rendered.comparison.passed());
    assert!(
        prepared
            .render_delivery(
                AnchorClocks::default(),
                &ExplicitRules,
                &std::collections::BTreeSet::from(["clock".into()]),
                |_| Ok(vec![json!(1042), json!(1042)])
            )
            .is_err()
    );
    assert!(
        prepared
            .render_delivery(
                clocks(),
                &ExplicitRules,
                &std::collections::BTreeSet::from(["clock".into()]),
                |_| Ok(vec![json!(1042), json!(2042)])
            )
            .is_err()
    );
}

#[test]
fn one_rule_identity_has_one_semantic_contract_across_all_registered_protocol_bindings() {
    let rule = Arc::new(ValueRule {
        id: "shared".into(),
        contract: FieldContract::Identity {
            prefix: String::new(),
            format: IdentityFormat::Decimal,
        },
    });
    let mut registry = BindingRegistry::new(traffic_extensions::codecs().clone());
    for name in ["native-a", "native-b"] {
        registry
            .register(
                name,
                MessageSide::Request,
                binding(rule.clone(), "first", "/id"),
                false,
            )
            .unwrap();
    }
    let conflict = Arc::new(ValueRule {
        id: "shared".into(),
        contract: FieldContract::Unordered,
    });
    assert!(
        registry
            .register(
                "native-b",
                MessageSide::Request,
                binding(conflict, "second", "/id"),
                false
            )
            .is_err()
    );
    assert_eq!(registry.for_protocol("native-b").request.len(), 1);
    assert!(registry.for_protocol("native-b").request[0].rule.contract == rule.contract);
}

#[test]
fn binding_evidence_identity_includes_runtime_time_anchors_and_native_locations() {
    let registry = |anchor, location| {
        let mut registry = BindingRegistry::new(traffic_extensions::codecs().clone());
        let rule = Arc::new(ValueRule {
            id: "clock".into(),
            contract: FieldContract::Time {
                format: TimestampFormat::UnixMicroseconds,
                relation: TimeRelation::PreserveOffset,
                anchor,
                utc_offset: None,
                clock_group: None,
                clock_scope: ClockScope::default(),
            },
        });
        registry
            .register(
                "native",
                MessageSide::Response,
                binding(rule, location, "/when"),
                true,
            )
            .unwrap();
        registry
    };
    let original = registry(TimeAnchor::Observation, "first");
    assert_eq!(
        original.signature().unwrap(),
        original.clone().signature().unwrap()
    );
    assert_ne!(
        original.signature().unwrap(),
        registry(TimeAnchor::DependencyRequestStart, "first")
            .signature()
            .unwrap()
    );
    assert_ne!(
        original.signature().unwrap(),
        registry(TimeAnchor::Observation, "second")
            .signature()
            .unwrap()
    );
}
