//! Application bindings for carrier-independent value execution.
use super::json::{self, AnchorClocks, Comparison, Field};
#[cfg(test)]
use super::time;
#[cfg(test)]
use crate::policy::GLOBAL_JSON_ID;
use crate::{
    policy::{CompiledJsonPolicy, CompiledRule},
    value_codec::DecodedValue,
};
use anyhow::{Context, Result};
use serde_json::Value;
use traffic_contract::compare::LogicalProjection;
use traffic_policy_execution::global as execution;

pub fn compare(
    source: &[u8],
    target: &[u8],
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if rules.is_empty()
        && let Ok(source) = crate::value_codec::sse::Document::decode(source)
    {
        let target = crate::value_codec::sse::Document::decode(target)
            .context("Target payload changed from Source SSE encoding")?;
        return crate::value_codec::sse::compare(&source, &target, plan, clocks);
    }
    execution::compare(
        &super::execution_context(),
        source,
        target,
        plan,
        rules,
        clocks,
    )
}

pub fn compare_decoded(
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare_decoded(
        &super::execution_context(),
        source,
        target,
        plan,
        rules,
        clocks,
    )
}

pub fn compare_decoded_with_time_copies(
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
) -> Result<Comparison> {
    let copies = super::copy_proofs(copies);
    execution::compare_decoded_with_time_copies(
        &super::execution_context(),
        source,
        target,
        plan,
        rules,
        clocks,
        &copies,
    )
}

pub fn compare_source_coverage(
    source: &[u8],
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if rules.is_empty() && crate::value_codec::sse::Document::decode(source).is_ok() {
        return compare(source, source, plan, rules, clocks);
    }
    execution::compare_source_coverage(&super::execution_context(), source, plan, rules, clocks)
}

#[allow(dead_code)]
pub fn compare_decoded_source_coverage(
    source: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare_decoded_source_coverage(
        &super::execution_context(),
        source,
        plan,
        rules,
        clocks,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn compare_logical(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare_logical(
        &super::execution_context(),
        source,
        target,
        plan,
        rules,
        clocks,
    )
}

pub fn compare_logical_with_time_copies(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
) -> Result<Comparison> {
    let copies = super::copy_proofs(copies);
    execution::compare_logical_with_time_copies(
        &super::execution_context(),
        source,
        target,
        plan,
        rules,
        clocks,
        &copies,
    )
}

pub fn policy_paths(
    source: &traffic_value::Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<Vec<String>> {
    execution::policy_paths(source, plan, clocks)
}

pub use execution::{prepare_fields, prepare_projected_fields};

pub fn compare_fields(
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    plan: &CompiledJsonPolicy,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare_fields(
        &super::execution_context(),
        source,
        target,
        plan,
        fields,
        clocks,
    )
}

pub fn compare_prepared_fields(
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    plan: &CompiledJsonPolicy,
    fields: &[Field<'_>],
    selected: &[traffic_policy_value::fields::SelectedGlobalField],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare_prepared_fields(
        &super::execution_context(),
        source,
        target,
        plan,
        fields,
        selected,
        clocks,
    )
}

pub fn compare_projected_fields(
    source: &LogicalProjection<'_>,
    target: &traffic_value::Value,
    plan: &CompiledJsonPolicy,
    fields: &[Field<'_>],
    selected: Option<&[traffic_policy_value::fields::SelectedGlobalField]>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare_projected_fields(
        &super::execution_context(),
        source,
        target,
        plan,
        fields,
        selected,
        clocks,
    )
}

#[allow(dead_code)]
pub fn compare_logical_with_verified(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
    additional: &[json::VerifiedField<'_>],
) -> Result<Comparison> {
    execution::compare_logical_with_verified(
        &super::execution_context(),
        source,
        target,
        plan,
        clocks,
        additional,
    )
}

#[cfg(test)]
pub fn materialize(
    source: &[u8],
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    execution::materialize(&super::execution_context(), source, plan, rules, clocks)
}

#[allow(dead_code)]
pub fn materialize_decoded(
    source: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    execution::materialize_decoded(&super::execution_context(), source, plan, rules, clocks)
}

pub fn materialize_logical(
    source: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    execution::materialize_logical(&super::execution_context(), source, plan, rules, clocks)
}

pub fn translate_times(
    source: &Value,
    delivered: &mut Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<()> {
    execution::translate_times(&super::execution_context(), source, delivered, plan, clocks)
}

pub fn translate_times_cow(
    source: &Value,
    delivered: &mut std::borrow::Cow<'_, Value>,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<()> {
    execution::translate_times_cow(&super::execution_context(), source, delivered, plan, clocks)
}

#[cfg(test)]
mod composition_tests;
#[cfg(test)]
mod tests;
