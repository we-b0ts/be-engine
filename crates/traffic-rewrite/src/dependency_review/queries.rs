//! Workflow entrypoints for independent attribution query projections.
use crate::RewriteContext;
use anyhow::{Context, Result};
use serde_json::Value;
pub(super) use traffic_rewrite_attribution::queries::candidate_page;
pub fn dependency_attribution_candidates(
    context: RewriteContext,
    investigation: &str,
    target: &str,
    revision: u64,
    offset: usize,
) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    traffic_rewrite_attribution::queries::dependency_attribution_candidates(
        &root,
        &state,
        investigation,
        target,
        revision,
        offset,
    )
}
pub fn dependency_attribution_rules(context: RewriteContext) -> Result<Value> {
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    traffic_rewrite_attribution::queries::dependency_attribution_rules(&root, &state)
}
