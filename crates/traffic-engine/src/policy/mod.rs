//! Traffic contracts, pure policy compilation and application runtime bindings.
//! Compilation is pure: evidence authorization and policy persistence belong to
//! their callers, and protocol adapters retain lane/session/consumption ownership.
mod authoring;
mod capability;
pub mod runtime;
pub use authoring::expanded as expand_policy;
pub use authoring::preserves_http_api_scope;
pub use authoring::require_source_proof;
pub use authoring::{effective_rules, render_policy, require_source_proofs};
pub use authoring::{legacy_authoring_error, retired_authoring};
mod async_api;
mod compiler;
mod declarations;
mod global_json;
mod http_global;
pub use async_api::*;
pub use http_global::*;
mod global_protocol;
mod mysql_global;
mod redis_global;
pub use declarations::*;
pub use global_json::*;
pub use global_protocol::*;
pub use mysql_global::*;
pub use redis_global::*;
pub mod native;
mod native_compile;
mod proof;
pub use proof::{MAX_PROOF_FACT_BYTES, MAX_PROOF_SOURCE_REFERENCES};
mod schema;
pub(crate) mod signatures;
pub use signatures::SignatureDefinition;
mod strict_map;
mod time_defaults;
mod time_scope;
pub use time_defaults::TimePolicy;
pub use time_scope::ClockScope;

pub use capability::*;
pub use compiler::*;
pub use native::{NativeEffect, NativeMatch, NativeRule, PolicyRule};
pub use native_compile::semantic_rule as native_semantics;
pub use native_compile::*;
pub use schema::*;

/// Compose pure compilation with the installed runtime's carrier admission.
pub fn compile_policy(document: &TrafficPolicy) -> anyhow::Result<CompiledPolicy> {
    let compiled = compiler::compile_definition(document)?;
    for rule in &compiled.native {
        validate_native_adapter(rule)?;
    }
    Ok(compiled)
}

pub fn parse_policy(yaml: &str) -> anyhow::Result<TrafficPolicy> {
    let document = compiler::decode_policy(yaml)?;
    compile_policy(&document)?;
    Ok(document)
}

pub fn parse_and_compile_policy(yaml: &str) -> anyhow::Result<CompiledPolicy> {
    compile_policy(&compiler::decode_policy(yaml)?)
}

pub fn compile_native(rule: &NativeRule) -> anyhow::Result<CompiledNativeRule> {
    let compiled = native_compile::compile_definition(rule)?;
    validate_native_adapter(&compiled)?;
    Ok(compiled)
}

fn validate_native_adapter(compiled: &CompiledNativeRule) -> anyhow::Result<()> {
    use anyhow::Context;
    runtime::validate_native_adapter(compiled).with_context(|| {
        format!(
            "native rule {:?} is unsupported by its typed adapter",
            compiled.rule.id
        )
    })
}

#[cfg(test)]
mod tests;

pub(crate) fn compilation_context() -> traffic_policy_compiler::CompilationContext<'static> {
    traffic_policy_compiler::CompilationContext {
        policies: traffic_extensions::policies(),
        codecs: traffic_extensions::codecs(),
    }
}

pub fn validate_field_claims(
    value: &[CompiledRule],
    native: &[CompiledNativeRule],
) -> anyhow::Result<()> {
    traffic_policy_compiler::native_compile::ownership::validate_field_claims(
        value,
        native,
        &compilation_context(),
    )
}

#[cfg(test)]
mod carrier_registration_tests;
