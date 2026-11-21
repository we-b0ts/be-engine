use super::*;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDescriptor, PolicyProvider,
    ValuePair,
};

struct BinaryPolicy;
impl PolicyProvider for BinaryPolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "fixture-binary",
            version: 1,
            description: "Compare an opaque binary suffix",
            actions: &[PolicyAction::Compare],
        }
    }
    fn prepare(&self, _: &traffic_value::Value) -> Result<Arc<dyn ComparisonPolicy>> {
        Ok(Arc::new(Self))
    }
}
impl ComparisonPolicy for BinaryPolicy {
    fn evaluate(&self, pair: &ValuePair<'_>, _: &mut dyn EvaluationHost) -> Result<Evaluation> {
        let (traffic_value::Value::Bytes(source), traffic_value::Value::Bytes(target)) =
            (pair.source, pair.target)
        else {
            anyhow::bail!("binary scalar type was lost");
        };
        Ok(if source.last() == target.last() {
            Evaluation::matched()
        } else {
            Evaluation::mismatch(pair, "binary_suffix", "binary suffix changed")
        })
    }
}

#[test]
fn binary_values_reach_registered_policies_and_delivery_without_array_coercion() {
    let contract = FieldContract::Policy(traffic_policy::PolicyDefinition::new("fixture-binary"));
    let mut binding = binding(
        Arc::new(ValueRule {
            id: "binary".into(),
            contract,
        }),
        "value",
        "",
    );
    binding.codec = Codec::registered("bytes", Value::Null).unwrap();
    let prepared = prepare(&RawDocument(b"\xff\x01"), &[binding]).unwrap();
    let mut registry = traffic_policy::PolicyRegistry::default();
    registry.register(Arc::new(BinaryPolicy)).unwrap();
    let metadata = traffic_contract::compare::RegisteredRules(&registry);
    assert!(
        prepared
            .compare(
                &RawDocument(b"\xfe\x01"),
                AnchorClocks::default(),
                &metadata
            )
            .unwrap()
            .passed()
    );
    assert!(
        !prepared
            .compare(
                &RawDocument(b"\xfe\x02"),
                AnchorClocks::default(),
                &metadata
            )
            .unwrap()
            .passed()
    );
    let rendered = prepared
        .render_values(
            &BTreeMap::from([("value".into(), json!([254, 1]))]),
            AnchorClocks::default(),
            &metadata,
        )
        .unwrap();
    assert_eq!(&rendered["value"][..], b"\xfe\x01");
    assert!(
        prepared
            .render_values(
                &BTreeMap::from([("value".into(), json!([254, 2]))]),
                AnchorClocks::default(),
                &metadata
            )
            .is_err()
    );
}

#[test]
fn typed_exact_comparison_distinguishes_bytes_arrays_and_numeric_categories() {
    use traffic_value::{Number, Value as Logical};
    let compare = |source: &Logical, target: &Logical| {
        compare::compare_logical_all(
            source,
            target,
            &[],
            &[],
            &[],
            AnchorClocks::default(),
            &[],
            &ExplicitRules,
        )
        .passed()
    };
    let bytes = Logical::Bytes(vec![1, 2]);
    let array = Logical::Array(vec![
        Logical::Number(Number::Unsigned(1)),
        Logical::Number(Number::Unsigned(2)),
    ]);
    assert!(compare(&bytes, &bytes));
    assert!(!compare(&bytes, &array));
    assert!(!compare(
        &Logical::Number(Number::Signed(1)),
        &Logical::Number(Number::Unsigned(1))
    ));
}
