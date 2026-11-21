use anyhow::{Context, Result};

use super::super::store::RewriteStore;
use super::super::{RewriteContext, inventory, worker};
use super::{
    ImplementerEvidence, RewriteEvidenceReport, RewriteState, RewriteWorkScope, implementer,
    overview,
};
use crate::RecordingApi;

/// Resolve a worker's exact assignment without activating it or advancing the workflow.
pub fn query_rewrite_evidence_for_scope(
    context: RewriteContext,
    scope: &RewriteWorkScope,
) -> Result<RewriteEvidenceReport> {
    with_implementer_scope(context, scope, |target_root, _, scoped, scope| {
        let issue = scoped.active_issue.as_ref().expect("validated issue");
        let query_id = overview::query_id(scoped, &scope, issue);
        overview::report(target_root, scoped, scope, issue, &query_id)
    })
}

/// Read the current API's implementer evidence without materializing the detail catalog.
pub fn query_implementer_evidence(
    context: RewriteContext,
    scope: &RewriteWorkScope,
) -> Result<ImplementerEvidence> {
    with_implementer_scope(context, scope, |target_root, state, scoped, scope| {
        implementer::report(target_root, state, scoped, &scope)
    })
}

fn with_implementer_scope<T>(
    context: RewriteContext,
    scope: &RewriteWorkScope,
    read: impl FnOnce(&std::path::Path, &RewriteState, &RewriteState, RewriteWorkScope) -> Result<T>,
) -> Result<T> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    match scope {
        RewriteWorkScope::Api { api } => {
            let scoped = super::super::api_selector::scoped(&state, api)?;
            let scope = super::super::api_selector::work_scope(&state, api);
            anyhow::ensure!(
                scoped.active_issue.is_some(),
                "{} has no current issue to diagnose",
                scope.label()
            );
            worker::ensure_scope_confirmed(&scoped, &scope, "querying evidence")?;
            read(&target_root, &state, &scoped, scope)
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
    let api = inventory::api_for_evidence_query(&state, query_id)
        .context("evidence query is stale or belongs to no concurrent API work item")?;
    worker::ensure_api_confirmed(&state, &api, "querying evidence")?;
    let scoped = inventory::scoped(&state, Some(&api.parse::<RecordingApi>()?))?;
    super::query(&target_root, &scoped, query_id)
}
