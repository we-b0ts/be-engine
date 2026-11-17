//! Application binding of pure capability checks to the installed catalog.
pub(crate) use traffic_policy_compiler::capability::validate_actual_protocol;
pub use traffic_policy_compiler::capability::{
    Capability, CapabilityId, FieldRequirement, capabilities,
};
pub fn validate_contract_binding(
    codec: &super::Codec,
    path: &str,
    contract: &super::FieldContract,
) -> anyhow::Result<()> {
    traffic_policy_compiler::capability::validate_contract_binding(
        codec,
        path,
        contract,
        &super::compilation_context(),
    )
}

#[cfg(test)]
pub(crate) fn validate_rule_coverage(
    rule: &super::Rule,
) -> anyhow::Result<traffic_policy_compiler::plan::RuleExecutionPlan> {
    traffic_policy_compiler::capability::validate_rule_coverage(rule, &super::compilation_context())
}

#[cfg(test)]
pub(crate) use traffic_policy_compiler::capability::validate_native_coverage;

#[cfg(test)]
mod coverage;

#[cfg(test)]
mod tests;
