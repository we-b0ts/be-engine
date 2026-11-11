//! Incremental source-backed API grouping. Project facts stay separate from workflow slots.
mod case_pattern_batch;
mod catalog;
mod model;

pub(super) use case_pattern_batch::{CasePatternAnalysisCommit, publication_pending};

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewritePhase, RewriteState,
};
use super::{action, api_selector, store::RewriteStore};
use model::{AnalysisSubmission, SCHEMA_VERSION};

pub use model::{
    RepositoryAnalysisApplyOptions, RepositoryAnalysisContext, RepositoryAnalysisContextOptions,
    RepositoryAnalysisSnapshot,
};

/// Reconcile only the in-memory project snapshot; the caller owns state persistence.
pub(super) fn refresh(root: &Path, state: &mut RewriteState) -> Result<bool> {
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
pub(in crate::rewrite) fn is_complete(state: &RewriteState) -> bool {
    state.implementers.is_none()
        || available(state)
            && state.repository_analysis.as_ref().is_some_and(|analysis| {
                selected_scope(state)
                    .iter()
                    .all(|api| analysis.api_groups.contains_key(api))
            })
}

pub(super) fn required_action(root: &Path, state: &RewriteState) -> Result<Option<RewriteAction>> {
    if !available(state) && state.case_pattern_identification.is_none() {
        return Ok(None);
    }
    let loaded = catalog::load(root)?;
    // Routine status must not rescan the Source snapshot after grouping is complete.
    if state.case_pattern_identification.is_none()
        && selected_scope(state)
            .iter()
            .all(|api| loaded.document.api_groups.contains_key(api))
    {
        return Ok(None);
    }
    let analysis = context_for_state(root, state, &loaded)?;
    Ok(Some(RewriteAction::RepositoryAnalysisRequired {
        summary: match &analysis.case_patterns {
            Some(patterns) => format!(
                "analyze {} unresolved case path(s) and group canonical APIs in one Source batch",
                patterns.candidates.len()
            ),
            None => format!(
                "group all {} ungrouped canonical API routes before Replay",
                analysis.pending_apis.len()
            ),
        },
        context: action::command(
            root,
            vec!["repository-analysis".into(), "context".into()],
            Vec::new(),
        ),
        apply: action::command(
            root,
            vec![
                "repository-analysis".into(),
                "apply".into(),
                analysis.batch_id.clone(),
            ],
            vec!["BACKEND_REWRITE_REPOSITORY_ANALYSIS_FILE".into()],
        ),
        analysis,
    }))
}

pub fn repository_analysis_context(
    options: RepositoryAnalysisContextOptions,
) -> Result<RepositoryAnalysisContext> {
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let state = RewriteStore::new(&root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    ensure!(
        available(&state) || state.case_pattern_identification.is_some(),
        "repository analysis requires a pending case pattern batch or an installed API inventory with an implementer pool"
    );
    context_for_state(&root, &state, &catalog::load(&root)?)
}

pub fn apply_repository_analysis(
    options: RepositoryAnalysisApplyOptions,
) -> Result<RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let submission: AnalysisSubmission = catalog::read_submission(&options.file)?;
    ensure!(
        submission.schema_version == SCHEMA_VERSION,
        "unsupported repository analysis submission schema version {}",
        submission.schema_version
    );
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    if let Some(envelope) =
        case_pattern_batch::apply(&root, &store, &mut state, &options.batch_id, &submission)?
    {
        return Ok(envelope);
    }
    ensure!(
        submission.case_patterns.is_none() && available(&state),
        "repository analysis has no matching batch for this submission"
    );
    let mut loaded = catalog::load(&root)?;
    let context = context_for_state(&root, &state, &loaded)?;
    let retry = !submission.assignments.is_empty()
        && submission
            .assignments
            .iter()
            .all(|(api, group)| loaded.document.api_groups.get(api) == Some(group));
    if retry {
        let pending = submission.assignments.keys().cloned().collect::<Vec<_>>();
        ensure!(
            pending.iter().all(|api| context.scope.contains(api))
                && options.batch_id == batch_id(&context, &pending, &submission.catalog_revision)?,
            "repository analysis retry differs from its original workflow scope or batch"
        );
    } else {
        ensure!(
            !context.pending_apis.is_empty(),
            "repository analysis has no ungrouped API routes"
        );
        ensure!(
            context.batch_id == options.batch_id,
            "repository analysis batch is stale; request fresh context"
        );
        ensure!(
            submission.catalog_revision == loaded.revision,
            "repository analysis catalog revision is stale; request fresh context"
        );
        apply_submission(&mut loaded.document, &context.pending_apis, &submission)?;
        catalog::publish(&root, &loaded.revision, &loaded.document)?;
    }
    if refresh(&root, &mut state)? {
        state.bump();
    }
    store.save(&state)?;
    Ok(action::advance_envelope(
        &root,
        &state,
        format!(
            "repository analysis batch {} was applied; continue canonical API scheduling",
            options.batch_id
        ),
    ))
}

fn available(state: &RewriteState) -> bool {
    state.implementers.is_some()
        && state.case_pattern_identification.is_none()
        && !state.api_inventory.is_empty()
        && state.phase != RewritePhase::RecordingRequired
}

fn context_for_state(
    root: &Path,
    state: &RewriteState,
    loaded: &catalog::LoadedCatalog,
) -> Result<RepositoryAnalysisContext> {
    if let Some(pending) = state.case_pattern_identification.as_ref() {
        return case_pattern_batch::context(root, state, pending, loaded);
    }
    let scope = selected_scope(state);
    let pending_apis = scope
        .iter()
        .filter(|api| !loaded.document.api_groups.contains_key(*api))
        .cloned()
        .collect::<Vec<_>>();
    let source_revision = crate::source_snapshot::source_runtime_revision(root)?;
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

fn batch_id(
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

fn selected_scope(state: &RewriteState) -> Vec<String> {
    state
        .api_inventory
        .iter()
        .filter(|item| item.status != RewriteApiStatus::Skipped)
        .map(|item| api_selector::public_api(&item.api).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn apply_submission(
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

#[cfg(test)]
mod tests;
