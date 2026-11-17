use super::*;
use traffic_policy::{
    AnalysisInput, EvidenceAccess, Finding, PolicyAction, PolicyDescriptor, PolicyProvider,
    PolicyRegistry,
};

struct FixturePolicy;
impl PolicyProvider for FixturePolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "fixture-policy",
            version: 1,
            description: "Extension-owned value diagnosis",
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
        if pair.source == pair.target {
            return Ok(Vec::new());
        }
        let values = evidence.query("source", &traffic_value::Value::Null)?;
        assert_eq!(values, vec![pair.source.clone()]);
        Ok(vec![Finding {
            policy: self.descriptor().id.into(),
            source_path: pair.source_path.into(),
            summary: "Fixture value differs".into(),
            hint: "Inspect the fixture's Source construction".into(),
            proposal: None,
            requirements: vec!["source_semantics".into()],
        }])
    }
}

#[test]
fn a_registered_analyzer_reaches_the_existing_hint_api_without_a_strategy_branch() {
    let mut registry = PolicyRegistry::default();
    registry
        .register(std::sync::Arc::new(FixturePolicy))
        .unwrap();
    let findings = crate::value_extensions::analyze_values(
        &registry,
        &traffic_value::Value::String("source".into()),
        &traffic_value::Value::String("target".into()),
        "/field",
        &serde_json::json!({}),
    )
    .unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    let facts = serde_json::json!({"policy_findings":[finding], "candidates":[]});
    let hints = rule_hints(Path::new("/project"), "extension-values", &facts);
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].rule, "fixture-policy");
    assert_eq!(hints[0].hint, finding.hint);
    let empty = crate::value_extensions::analyze_values(
        &PolicyRegistry::default(),
        &traffic_value::Value::String("source".into()),
        &traffic_value::Value::String("target".into()),
        "/field",
        &serde_json::json!({}),
    )
    .unwrap();
    assert!(empty.is_empty());
}

#[test]
fn removing_policy_registration_removes_context_diagnostics() {
    let facts = serde_json::json!({"query":"dirty_clusters","clusters":[
        {"protocol":"custom-native","reason":"unmatched_target"}
    ], "egress_rejections":{"rejected_packets_in_samples":2}});
    let installed =
        crate::value_extensions::analyze_context(traffic_extensions::policies(), &facts).unwrap();
    assert!(
        installed
            .iter()
            .any(|finding| finding.policy == "unordered")
    );
    assert!(
        installed
            .iter()
            .any(|finding| finding.policy == "documents")
    );
    let empty =
        crate::value_extensions::analyze_context(&PolicyRegistry::default(), &facts).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn an_unmatched_literal_ip_triggers_registered_acquisition_diagnosis() {
    let facts = serde_json::json!({"query":"dirty_clusters","clusters":[{
        "protocol":"custom-native","reason":"unmatched_target",
        "endpoint":{"host":"10.0.0.1","port":6379}
    }]});
    let findings =
        crate::value_extensions::analyze_context(traffic_extensions::policies(), &facts).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.policy == "documents")
        .unwrap();
    assert!(
        finding
            .requirements
            .iter()
            .any(|requirement| requirement == "recording")
    );
    assert!(finding.proposal.is_none());
}
