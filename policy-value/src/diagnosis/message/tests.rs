use super::*;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use traffic_policy::{
    AnalysisInput, EvidenceAccess, PolicyAction, PolicyDescriptor, PolicyProvider,
};
use traffic_protocol::message::{ProjectedMessage, ProjectedValue};

struct Message(Vec<u8>);
impl ProtocolMessage for Message {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"native":"fixture"}),
            values: BTreeMap::from([(
                "opaque-native-location".into(),
                ProjectedValue::json(self.0.clone()),
            )]),
        })
    }
    fn locate(&self, _: &Value) -> Result<Vec<String>> {
        Ok(vec!["opaque-native-location".into()])
    }
    fn evidence(&self, _: &Value) -> Result<Value> {
        Ok(Value::Null)
    }
}
fn message(value: Value) -> Message {
    Message(serde_json::to_vec(&value).unwrap())
}

struct Analyzer;
impl PolicyProvider for Analyzer {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "fixture-analysis",
            version: 1,
            description: "Fixture logical field analysis",
            actions: &[PolicyAction::Analyze],
        }
    }
    fn analyze(
        &self,
        input: &AnalysisInput<'_>,
        evidence: &dyn EvidenceAccess,
    ) -> Result<Vec<Finding>> {
        let Some(pair) = &input.values else {
            return Ok(Vec::new());
        };
        if pair.source_path != "/field" {
            return Ok(Vec::new());
        }
        assert_eq!(
            evidence.query("source", &traffic_value::Value::Null)?,
            vec![pair.source.clone()]
        );
        Ok(vec![Finding {
            policy: "fixture-analysis".into(),
            source_path: pair.source_path.into(),
            summary: "Fixture field differs".into(),
            hint: "Inspect the fixture Source field".into(),
            proposal: None,
            requirements: vec!["source_semantics".into()],
        }])
    }
}

#[test]
fn registered_analyzers_receive_decoded_values_from_arbitrary_native_locations() {
    let source = message(json!({"field":"source"}));
    let target = message(json!({"field":"target"}));
    let mut policies = PolicyRegistry::default();
    policies.register(Arc::new(Analyzer)).unwrap();
    let findings = analyze(
        &source,
        &target,
        traffic_extensions::codecs(),
        &policies,
        &differences(),
        &json!({}),
    )
    .unwrap();
    assert!(!findings.limited);
    assert_eq!(findings.findings.len(), 1);
    assert_eq!(
        findings.findings[0].native_location,
        "opaque-native-location"
    );
    assert_eq!(findings.findings[0].finding.source_path, "/field");
    assert!(
        analyze(
            &source,
            &target,
            traffic_extensions::codecs(),
            &PolicyRegistry::default(),
            &differences(),
            &json!({})
        )
        .unwrap()
        .findings
        .is_empty()
    );
    assert!(
        analyze(
            &source,
            &source,
            traffic_extensions::codecs(),
            &policies,
            &differences(),
            &json!({})
        )
        .unwrap()
        .findings
        .is_empty()
    );
}

#[test]
fn registered_collection_analysis_is_bounded_without_authorizing_a_comparison() {
    let source = message(Value::Object(
        (0..20)
            .map(|index| (format!("field-{index}"), json!([1, 2, 1])))
            .collect(),
    ));
    let target = message(Value::Object(
        (0..20)
            .map(|index| (format!("field-{index}"), json!([1, 1, 2])))
            .collect(),
    ));
    let result = analyze(
        &source,
        &target,
        traffic_extensions::codecs(),
        traffic_extensions::policies(),
        &differences(),
        &json!({}),
    )
    .unwrap();
    assert_eq!(result.findings.len(), MAX_FINDINGS);
    assert!(result.limited);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.finding.policy == "unordered")
    );
}

fn differences() -> Vec<traffic_contract::comparison::Difference> {
    vec![traffic_contract::comparison::Difference {
        pointer: "opaque-native-location".into(),
        reason: "changed".into(),
    }]
}

#[test]
fn permitted_field_changes_are_excluded_from_candidate_analysis() {
    let source = message(json!({"field":"source", "other":"same"}));
    let target = message(json!({"field":"target", "other":"same"}));
    let mut policies = PolicyRegistry::default();
    policies.register(Arc::new(Analyzer)).unwrap();
    let differences = vec![traffic_contract::comparison::Difference {
        pointer: "opaque-native-location/other".into(),
        reason: "focused failure".into(),
    }];
    assert!(
        analyze(
            &source,
            &target,
            traffic_extensions::codecs(),
            &policies,
            &differences,
            &json!({})
        )
        .unwrap()
        .findings
        .is_empty()
    );
}
