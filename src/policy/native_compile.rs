//! Application admission follows pure native compilation.
#[cfg(test)]
use super::{Proof, Protocol, TimestampFormat, native::*};
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use traffic_policy_compiler::native_compile::time::validate_time;
pub use traffic_policy_compiler::native_compile::{
    ClaimSurface, CompiledNativeRule, NativeDomain, NativeFieldClaim, NativeOwnedSlot,
    OwnedElement, OwnedFieldCondition, OwnedLocation, native_field_claims, semantic_rule,
    validate_startup_key, value_sql_scopes_overlap, value_sql_slots_overlap,
};

pub(super) fn compile_definition(rule: &super::NativeRule) -> anyhow::Result<CompiledNativeRule> {
    traffic_policy_compiler::native_compile::compile_definition(rule, &super::compilation_context())
}

#[cfg(test)]
mod tests;
