//! Application bindings for prepared declarations and installed value codecs.
use super::json::{AnchorClocks, Comparison};
use crate::{
    policy::{Codec, CompiledRule},
    value_codec::CodecPlan,
};
use anyhow::Result;
use std::sync::Arc;
use traffic_policy_execution::encoded as execution;

pub fn merged_codec(rules: &[&CompiledRule]) -> Result<Codec> {
    execution::merged_codec(&super::execution_context(), rules)
}

#[allow(dead_code)]
pub fn prepared_codec(rules: &[&CompiledRule]) -> Result<Arc<CodecPlan>> {
    execution::prepared_codec(&super::execution_context(), rules)
}

#[allow(dead_code)]
pub fn compare(
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    execution::compare(&super::execution_context(), source, target, rules, clocks)
}

pub use execution::comparison_paths;

pub fn merge_codec(codec: &mut Codec, next: &Codec) -> Result<()> {
    execution::merge_codec(&super::execution_context(), codec, next)
}

#[cfg(test)]
mod prepared {
    pub(super) use traffic_policy_execution::encoded::prepared::{clear, occupancy};
}
#[cfg(test)]
mod tests;
