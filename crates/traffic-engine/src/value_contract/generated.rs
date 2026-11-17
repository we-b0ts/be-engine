//! Application compatibility bindings for independently owned generated-value contracts.
pub(crate) use traffic_policy_generated::{compare_bounded_random, validate_bounded_random};
pub(crate) mod template {
    pub(crate) use traffic_policy_generated::template::valid_token;
}

#[cfg(test)]
use super::json::{self, AnchorClocks, Comparison};
#[cfg(test)]
use crate::policy::native::GeneratedResponse;
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use traffic_policy_generated::GeneratedError;

#[cfg(test)]
fn compare_value(
    source: &Value,
    target: &Value,
    contract: &GeneratedResponse,
    key: Option<&[u8]>,
    rule_id: &str,
    clocks: AnchorClocks,
) -> Result<Comparison, GeneratedError> {
    traffic_policy_generated::compare_value(
        &super::execution_context(),
        source,
        target,
        contract,
        key,
        rule_id,
        clocks,
    )
}

#[cfg(test)]
fn compare_value_global(
    source: &Value,
    target: &Value,
    contract: &GeneratedResponse,
    key: Option<&[u8]>,
    rule_id: &str,
    clocks: AnchorClocks,
    global: Option<&crate::policy::CompiledJsonPolicy>,
) -> Result<Comparison, GeneratedError> {
    traffic_policy_generated::compare_value_global(
        &super::execution_context(),
        source,
        target,
        contract,
        key,
        rule_id,
        clocks,
        global.map(|plan| plan as &dyn traffic_policy_value::formats::FormatHost),
    )
}

#[cfg(test)]
mod tests;
