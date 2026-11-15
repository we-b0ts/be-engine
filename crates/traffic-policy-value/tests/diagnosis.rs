use anyhow::Result;
use std::sync::Arc;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDescriptor, PolicyProvider,
    PolicyRegistry, ValuePair,
};
use traffic_policy_value::diagnosis;
use traffic_value::Value;

fn logical(value: serde_json::Value) -> Value {
    serde_json::from_value(value).unwrap()
}

#[test]
fn collection_diagnosis_preserves_unselected_values_and_nested_array_order() {
    let policy = traffic_extensions::policies()
        .prepare("unordered", &Value::Null)
        .unwrap();
    let source = logical(serde_json::json!({"a/b":[[1,2],[3,4]],"exact":1}));
    let target = logical(serde_json::json!({"a/b":[[3,4],[1,2]],"exact":2}));
    let paths = diagnosis::discover(&policy, &source, &target, false).unwrap();
    assert_eq!(paths, ["/a~1b"]);
    let mut left = source;
    let mut right = target;
    assert!(!diagnosis::normalize(&policy, &mut left, &mut right, &paths[0]).unwrap());
    assert_eq!(left.pointer("/exact"), Some(&logical(serde_json::json!(1))));
    assert_ne!(left, right);
}

#[test]
fn selected_wildcard_locations_keep_duplicate_counts() {
    let policy = traffic_extensions::policies()
        .prepare("unordered", &Value::Null)
        .unwrap();
    let mut source = logical(serde_json::json!({"items":[{"values":[1,1,2]}]}));
    let mut target = logical(serde_json::json!({"items":[{"values":[2,1,1]}]}));
    assert!(diagnosis::normalize(&policy, &mut source, &mut target, "/items/*/values").unwrap());
    target = logical(serde_json::json!({"items":[{"values":[2,2,1]}]}));
    assert!(!diagnosis::normalize(&policy, &mut source, &mut target, "/items/*/values").unwrap());
}

#[test]
fn root_selection_is_explicit_and_bytes_keep_scalar_identity() {
    let policy = traffic_extensions::policies()
        .prepare("unordered", &Value::Null)
        .unwrap();
    let source = logical(serde_json::json!([1, 2]));
    let target = logical(serde_json::json!([2, 1]));
    assert!(
        diagnosis::discover(&policy, &source, &target, false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        diagnosis::discover(&policy, &source, &target, true).unwrap(),
        [""]
    );
    assert!(
        diagnosis::discover(
            &policy,
            &Value::Bytes(vec![1, 2]),
            &Value::Bytes(vec![2, 1]),
            true
        )
        .unwrap()
        .is_empty()
    );
    assert!(
        PolicyRegistry::default()
            .prepare("unordered", &Value::Null)
            .is_err()
    );
}

struct CaseFold;

impl PolicyProvider for CaseFold {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "test.case-fold",
            version: 1,
            description: "ASCII case-folding extension",
            actions: &[PolicyAction::Compare, PolicyAction::Infer],
        }
    }
    fn prepare(&self, _: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        Ok(Arc::new(Self))
    }
    fn infer(&self, source: &Value, _: &Value) -> Result<Option<traffic_policy::PolicyInference>> {
        Ok(source.as_str().map(|_| traffic_policy::PolicyInference {
            rule_id: "builtin.test.case-fold",
            definition: traffic_policy::PolicyDefinition::new("test.case-fold"),
            declaration: None,
        }))
    }
}

impl ComparisonPolicy for CaseFold {
    fn canonical_value(&self, value: &Value) -> Result<Option<Value>> {
        Ok(value
            .as_str()
            .map(|text| Value::String(text.to_ascii_lowercase())))
    }
    fn evaluate(&self, pair: &ValuePair<'_>, _: &mut dyn EvaluationHost) -> Result<Evaluation> {
        Ok(
            if self.canonical_value(pair.source)? == self.canonical_value(pair.target)? {
                Evaluation::matched()
            } else {
                Evaluation::mismatch(pair, "case_fold", "folded values differ")
            },
        )
    }
}

#[test]
fn an_independently_registered_policy_uses_the_same_discovery_and_normalization() {
    let mut registry = PolicyRegistry::default();
    registry.register(Arc::new(CaseFold)).unwrap();
    let policy = registry.prepare("test.case-fold", &Value::Null).unwrap();
    let mut source = logical(serde_json::json!({"value":"Hello"}));
    let mut target = logical(serde_json::json!({"value":"HELLO"}));
    assert_eq!(
        diagnosis::discover(&policy, &source, &target, false).unwrap(),
        ["/value"]
    );
    assert!(diagnosis::normalize(&policy, &mut source, &mut target, "/value").unwrap());
}

#[test]
fn an_independent_policy_supplies_source_applicability_and_reaches_shared_comparison() {
    let mut registry = PolicyRegistry::default();
    registry.register(Arc::new(CaseFold)).unwrap();
    let source = logical(serde_json::json!({"value":"Hello","exact":3}));
    let target = logical(serde_json::json!({"value":"HELLO","exact":3}));
    let selected =
        traffic_policy_value::inference::fields(&registry, &source, &Value::Null).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].pointer, "/value");
    let fields = selected
        .iter()
        .map(|field| traffic_contract::compare::Field {
            rule_id: field.rule_id,
            pointer: &field.pointer,
            contract: &field.contract,
        })
        .collect::<Vec<_>>();
    let comparison = traffic_contract::compare::compare_logical_all(
        &source,
        &target,
        &fields,
        &[],
        &[],
        Default::default(),
        &[],
        &traffic_contract::compare::RegisteredRules(&registry),
    );
    assert!(comparison.passed());
    assert!(
        traffic_policy_value::inference::fields(&PolicyRegistry::default(), &source, &Value::Null)
            .unwrap()
            .is_empty()
    );
    assert!(
        traffic_policy_value::inference::fields(
            &registry,
            &Value::Bytes(vec![65, 66]),
            &Value::Null
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn field_plans_apply_the_supplied_catalog_to_authored_and_inferred_values() {
    use std::collections::BTreeMap;
    use traffic_policy_value::fields::{FieldPlan, GlobalField, TimePolicy, validate_fields};

    let mut registry = PolicyRegistry::default();
    registry.register(Arc::new(CaseFold)).unwrap();
    let authored = BTreeMap::from([(
        "/explicit".into(),
        GlobalField::Policy(traffic_policy::PolicyDefinition::new("test.case-fold")),
    )]);
    let settings = TimePolicy::default();
    validate_fields(&authored, &settings, &registry).unwrap();
    assert!(validate_fields(&authored, &settings, &PolicyRegistry::default()).is_err());
    let plan = FieldPlan::new(&authored, &settings, &registry);
    let source = logical(serde_json::json!({"explicit":"Hello","automatic":"World","strict":3}));
    let selected = plan
        .selected_value_fields_with_clocks(&source, Default::default())
        .unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].pointer, "/automatic");
    assert_eq!(selected[0].rule_id, "builtin.test.case-fold");
    assert_eq!(selected[1].pointer, "/explicit");
    assert_eq!(
        selected[1].rule_id,
        traffic_policy_value::fields::GLOBAL_JSON_ID
    );
}
