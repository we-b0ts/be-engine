use super::*;
use traffic_contract::compare::RegisteredRules;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDefinition, PolicyDescriptor,
    PolicyProvider, PolicyRegistry, ValuePair,
};

struct Reject;
impl PolicyProvider for Reject {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "reject-equal",
            version: 1,
            description: "Validate a selected scalar even when its bytes are equal",
            actions: &[PolicyAction::Compare],
        }
    }
    fn prepare(&self, _: &traffic_value::Value) -> Result<Arc<dyn ComparisonPolicy>> {
        Ok(Arc::new(Self))
    }
}
impl ComparisonPolicy for Reject {
    fn evaluate(&self, pair: &ValuePair<'_>, _: &mut dyn EvaluationHost) -> Result<Evaluation> {
        Ok(Evaluation::mismatch(
            pair,
            "rejected",
            "selected scalar requires validation",
        ))
    }
}

#[test]
fn selected_policies_validate_equal_scalars_through_the_comparison_port() {
    let mut policies = PolicyRegistry::default();
    policies.register(Arc::new(Reject)).unwrap();
    let metadata = RegisteredRules(&policies);
    let codecs = traffic_extensions::codecs();
    let context = ExecutionContext {
        codecs,
        metadata: &metadata,
    };
    let field = GlobalField::Policy(PolicyDefinition::new("reject-equal"));
    let comparison = compare(
        &context,
        "physical-field",
        b"same",
        b"same",
        &field,
        &TimePolicy::default(),
        AnchorClocks::default(),
        &[],
    )
    .unwrap();
    assert!(!comparison.passed());
    assert!(comparison.evaluated.contains("physical-field"));
}
