//! Application composition supplies generated leaves with installed execution services.
use super::Comparison;
pub(crate) use traffic_policy_generated::Field as NativeField;

pub(super) fn verifier<'a>(
    field: &'a NativeField<'_>,
) -> impl Fn(traffic_contract::compare::NativeContext<'_>) -> Result<Comparison, String> + 'a {
    traffic_policy_generated::verifier(crate::value_contract::execution_context(), field)
}
