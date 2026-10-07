use anyhow::{Context, Result};

use super::super::store::RewriteStore;
use super::super::{RewriteContext, inventory, worker};
use super::{RewriteEvidenceReport, RewriteWorkScope, overview};
use crate::RecordingApi;

/// Resolve a worker's exact assignment without activating it or advancing the workflow.
pub fn query_rewrite_evidence_for_scope(
    context: RewriteContext,
    scope: &RewriteWorkScope,
) -> Result<RewriteEvidenceReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    match scope {
        RewriteWorkScope::Api { api } => {
            let scoped = super::super::api_selector::scoped(&state, api)?;
            let scope = super::super::api_selector::work_scope(&state, api);
            let issue = scoped
                .active_issue
                .as_ref()
                .with_context(|| format!("{} has no current issue to diagnose", scope.label()))?;
            worker::ensure_scope_confirmed(&scoped, &scope, "querying evidence")?;
            let query_id = overview::query_id(&scoped, &scope, issue);
            overview::report(&target_root, &scoped, scope, issue, &query_id)
        }
        RewriteWorkScope::ProcessOutput { id } => {
            let item = state
                .process_outputs
                .inventory
                .iter()
                .find(|item| item.id == *id)
                .with_context(|| format!("process-output inventory does not contain {id:?}"))?;
            let issue = item
                .issue
                .as_ref()
                .with_context(|| format!("{} has no current issue to diagnose", scope.label()))?;
            worker::ensure_scope_confirmed(&state, scope, "querying evidence")?;
            let query_id = overview::query_id(&state, scope, issue);
            overview::report(&target_root, &state, scope.clone(), issue, &query_id)
        }
    }
}

/// Execute an issue-bound overview, detail, or pagination query returned by the engine.
pub fn query_rewrite_evidence(
    context: RewriteContext,
    query_id: &str,
) -> Result<RewriteEvidenceReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    if let Some(report) = overview::query_process_output(&target_root, &state, query_id)? {
        return Ok(report);
    }
    let api = inventory::api_for_evidence_query(&state, query_id)
        .context("evidence query is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "querying evidence")?;
    let scoped = inventory::scoped(&state, Some(&api.parse::<RecordingApi>()?))?;
    super::query(&target_root, &scoped, query_id)
}
