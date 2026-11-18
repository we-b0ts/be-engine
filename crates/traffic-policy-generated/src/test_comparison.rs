//! Test composition exercises generated leaves through the shared comparison kernel.
pub use super::Field as NativeField;
use super::*;
pub use traffic_contract::compare::Field;

struct Metadata;
impl traffic_contract::compare::RuleMetadata for Metadata {
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        traffic_extensions::policies()
    }
    fn permits_scalar_composition(&self, rule: &str) -> bool {
        rule == "global.json"
    }
    fn accepts_exact_time(&self, rule: &str) -> bool {
        matches!(
            rule,
            "global.json" | "global.http" | "global.redis" | "global.mysql" | "builtin.time"
        )
    }
}

pub(super) fn context() -> ExecutionContext<'static> {
    ExecutionContext {
        codecs: traffic_extensions::codecs(),
        metadata: &Metadata,
    }
}

pub(super) fn compare_with_native(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    let context = context();
    let verifiers = native
        .iter()
        .map(|field| super::verifier(context, field))
        .collect::<Vec<_>>();
    let native = native
        .iter()
        .zip(&verifiers)
        .map(|(field, verifier)| traffic_contract::compare::NativeField {
            rule_id: field.rule_id,
            pointer: field.pointer,
            verifier,
        })
        .collect::<Vec<_>>();
    traffic_contract::compare::compare_all(
        source,
        target,
        fields,
        &native,
        &[],
        clocks,
        &[],
        context.metadata,
    )
}
