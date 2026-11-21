use super::*;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDescriptor, PolicyProvider,
    PolicyRegistry, ValuePair,
};
use traffic_value::Value as Logical;

struct TenantIdentity;

impl PolicyProvider for TenantIdentity {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "tenant-identity",
            version: 1,
            description: "Tenant-prefixed identifiers supplied by an extension",
            actions: &[PolicyAction::Compare],
        }
    }

    fn prepare(&self, options: &Logical) -> Result<Arc<dyn ComparisonPolicy>> {
        ensure!(options == &Logical::Null, "tenant identity has no options");
        Ok(Arc::new(Self))
    }
}

impl ComparisonPolicy for TenantIdentity {
    fn applies(&self, value: &Logical, _: &Logical) -> Result<bool> {
        Ok(value
            .as_str()
            .and_then(|value| value.strip_prefix("tenant/"))
            .is_some_and(|value| {
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_uppercase())
            }))
    }

    fn evaluate(&self, pair: &ValuePair<'_>, host: &mut dyn EvaluationHost) -> Result<Evaluation> {
        host.relate(pair)?;
        Ok(Evaluation::matched())
    }
}

#[test]
fn delivery_uses_an_installed_custom_policy_for_source_and_resolved_values() {
    let mut policies = PolicyRegistry::default();
    policies.register(Arc::new(TenantIdentity)).unwrap();
    let policy = policies.prepare("tenant-identity", &Logical::Null).unwrap();
    assert!(PreparedIdentityDelivery::prepare(&json!("tenant/invalid"), policy.clone()).is_err());

    let selected = PreparedIdentityDelivery::prepare(&json!("tenant/OLD"), policy).unwrap();
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("tenant/OLD", "tenant/NEW")]))
        .unwrap();
    let (values, pending) = store.deliveries("case", &[selected]).unwrap();
    assert_eq!(values, vec![json!("tenant/NEW")]);
    store.commit(pending).unwrap();

    let selected = PreparedIdentityDelivery::prepare(
        &json!("tenant/OTHER"),
        policies.prepare("tenant-identity", &Logical::Null).unwrap(),
    )
    .unwrap();
    store
        .commit(decision(
            "case",
            vec![pair("tenant/OTHER", "tenant/invalid")],
        ))
        .unwrap();
    assert!(store.deliveries("case", &[selected]).is_err());
    assert!(
        store
            .contains_pair("case", pair("tenant/OLD", "tenant/NEW"))
            .unwrap()
    );
}
