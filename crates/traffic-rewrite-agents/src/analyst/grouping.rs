//! Validate grouping assignments against the immutable catalog and selected routes.
use super::{
    catalog,
    model::{self, AnalysisSubmission, RepositoryAnalysisContext, SCHEMA_VERSION},
};
use crate::api_selector;
use anyhow::{Result, ensure};
use std::{collections::BTreeSet, path::Path};
use traffic_engine::source_snapshot;
use traffic_rewrite_model::rewrite::{RewriteApiStatus, RewritePhase, RewriteState};
/// Reconcile only the in-memory project snapshot; the caller owns state persistence.
pub fn refresh(root: &Path, state: &mut RewriteState) -> Result<bool> {
    if state.implementers.is_none() {
        return Ok(false);
    }
    let snapshot = catalog::load(root)?.snapshot();
    if state.repository_analysis.as_ref() == Some(&snapshot) {
        return Ok(false);
    }
    state.repository_analysis = Some(snapshot);
    Ok(true)
}

/// Dispatch admission uses the adopted snapshot without reading Source or catalog files.
pub fn is_complete(state: &RewriteState) -> bool {
    state.implementers.is_none()
        || available(state)
            && state.repository_analysis.as_ref().is_some_and(|analysis| {
                selected_scope(state)
                    .iter()
                    .all(|api| analysis.api_groups.contains_key(api))
            })
}

pub fn available(state: &RewriteState) -> bool {
    state.implementers.is_some()
        && state.case_pattern_identification.is_none()
        && !state.api_inventory.is_empty()
        && state.phase != RewritePhase::RecordingRequired
}

pub fn context(
    root: &Path,
    state: &RewriteState,
    loaded: &catalog::LoadedCatalog,
) -> Result<RepositoryAnalysisContext> {
    let scope = selected_scope(state);
    let pending_apis = scope
        .iter()
        .filter(|api| !loaded.document.api_groups.contains_key(*api))
        .cloned()
        .collect::<Vec<_>>();
    let source_revision = source_snapshot::source_runtime_revision(root)?;
    let mut context = RepositoryAnalysisContext {
        schema_version: SCHEMA_VERSION,
        workflow_id: state.workflow_id.clone(),
        recording_run_id: state.recording_run_id.clone(),
        source_revision,
        scope,
        pending_apis,
        case_patterns: None,
        batch_id: String::new(),
        catalog_path: catalog::path(root),
        catalog_revision: loaded.revision.clone(),
    };
    context.batch_id = batch_id(&context, &context.pending_apis, &loaded.revision)?;
    Ok(context)
}

pub fn batch_id(
    context: &RepositoryAnalysisContext,
    pending: &[String],
    revision: &str,
) -> Result<String> {
    let identity = serde_json::to_vec(&(
        &context.workflow_id,
        &context.recording_run_id,
        &context.source_revision,
        &context.scope,
        pending,
        revision,
    ))?;
    Ok(format!(
        "repository-analysis-{}",
        catalog::digest(&identity).trim_start_matches("sha256:")
    ))
}

pub fn selected_scope(state: &RewriteState) -> Vec<String> {
    state
        .api_inventory
        .iter()
        .filter(|item| item.status != RewriteApiStatus::Skipped)
        .map(|item| api_selector::public_api(&item.api).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn apply_submission(
    document: &mut model::CatalogDocument,
    pending: &[String],
    submission: &AnalysisSubmission,
) -> Result<()> {
    let actual = submission
        .assignments
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = pending.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        actual == expected,
        "repository analysis assignments must cover exactly the pending canonical API routes"
    );
    for (api, id) in &submission.assignments {
        catalog::route(api)?;
        ensure!(
            !document.api_groups.contains_key(api),
            "existing API group assignment is read-only: {api}"
        );
        catalog::group_id(id)?;
    }
    document.api_groups.extend(submission.assignments.clone());
    Ok(())
}
