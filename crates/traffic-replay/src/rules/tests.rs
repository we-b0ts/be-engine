use super::*;
use serde_json::json;
use traffic_contract::{
    compare::ExplicitRules,
    identity::{IdentityDecision, IdentityPair, IdentityStore, PreparedIdentityDelivery},
    rule::{ClockScope, IdentityFormat, TimeAnchor, TimeRelation, TimestampFormat},
    time::ClockPair,
};

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
    let prepared = PreparedMessage::compile(
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
            &ExplicitRules,
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
    let mut registry = BindingRegistry::default();
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
        let mut registry = BindingRegistry::default();
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
