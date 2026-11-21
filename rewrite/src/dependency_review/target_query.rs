//! Workflow entrypoint for bounded authenticated Target observation reads.
use crate::RewriteContext;
use anyhow::{Context, Result};
use serde_json::Value;
use traffic_rewrite_evidence::target_observation::TargetObservationQuery;
pub(super) use traffic_rewrite_evidence::target_observation::inventory;

pub fn dependency_attribution_target(
    context: RewriteContext,
    session: &str,
    observation: &str,
    pointer: &str,
) -> Result<Value> {
    let query = TargetObservationQuery::new(session, observation, pointer)?;
    let (root, store) = super::open(&context.target_root)?;
    let state = store.load()?.context("rewrite workflow absent")?;
    query.read(&root, &state)
}
