//! JSON adapter over the shared typed hypothesis kernel.
pub use super::hypothesis::Candidate;
#[cfg(test)]
use super::json::{AnchorClocks, Comparison};
#[cfg(test)]
use crate::policy::CompiledJsonPolicy;

#[cfg(test)]
pub fn preview(
    case: &str,
    source: &[u8],
    target: &[u8],
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Option<Comparison> {
    super::hypothesis::preview_json(case, source, target, plan, clocks).comparison
}

#[cfg(test)]
mod tests;
