//! Immutable analyst context derived from a sealed admission inventory.
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use traffic_rewrite_model::rewrite::dependency_review::assignment_id;
use traffic_rewrite_model::rewrite::{
    dependency_review::model::{AttributionReviewContext, ClaimStatus, SCHEMA},
    model::RewriteState,
};

pub fn from_inventory(
    state: &RewriteState,
    identity: &str,
    unattributed_exchange_ids: BTreeSet<uuid::Uuid>,
) -> Result<AttributionReviewContext> {
    let source_revision = state
        .source_revision
        .clone()
        .context("Source revision absent")?;
    let claims = state
        .dependency_review
        .claims
        .values()
        .filter(|claim| {
            claim.recording_run_id == state.recording_run_id
                && matches!(claim.status, ClaimStatus::Pending | ClaimStatus::Unresolved)
        })
        .cloned()
        .collect();
    let assignment_id = assignment_id(state)?;
    Ok(AttributionReviewContext {
        schema: SCHEMA,
        work_type: "dependency_attribution",
        workflow_id: state.workflow_id.clone(),
        recording_run_id: state.recording_run_id.clone(),
        source_revision,
        source_inventory_id: identity.into(),
        revision: state.dependency_review.revision,
        assignment_id,
        claims,
        task_groups: BTreeMap::new(),
        client_abort_origins: vec![],
        evidence_commands: vec![],
        effective_policy_fingerprint: String::new(),
        rule_groups: vec![],
        rule_planning: serde_json::Value::Null,
        unattributed_exchange_ids,
        unattributed: Default::default(),
        obligations: state
            .dependency_review
            .obligations
            .values()
            .filter(|o| o.pending())
            .cloned()
            .collect(),
        next_step: "Complete independent Source ownership analysis first, then assess whether effective process/async lifecycle rules are missing, incomplete or sufficient. For each async origin, inspect its complete effective Case inventory (original ownership plus newly assigned occurrences) and return the scenario's end proposal under recording.async_api or identify existing coverage. Derive request templates, reply/message conditions and total matching occurrence counts from the analyzed tail; do not enumerate intermediate dependencies. For a necessary rule change, the coordinator uses rule_planning to plan/apply, obtains fresh context, then rebinds and applies the already established exact-occurrence proof. No unchanged plan or repeated ownership analysis is required. Reject mistaken returns with Source proof; missing traffic stays with its reporting API, and ownership never proves consumption.",
    })
}
