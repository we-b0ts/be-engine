//! Incremental source-backed API grouping. Project facts stay separate from workflow slots.
mod case_pattern_batch;
mod catalog;
mod model;

pub(super) use case_pattern_batch::publication_pending;

use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::model::{RewriteAction, RewriteActionEnvelope, RewriteState};
#[cfg(test)]
use super::model::{RewriteApiStatus, RewritePhase};
use super::{action, store::RewriteStore};
use model::{AnalysisSubmission, SCHEMA_VERSION};

pub use model::{
    RepositoryAnalysisApplyOptions, RepositoryAnalysisContext, RepositoryAnalysisContextOptions,
    RepositoryAnalysisSnapshot,
};

#[cfg(test)]
pub(crate) use traffic_rewrite_agents::analyst::grouping::is_complete;
pub(crate) use traffic_rewrite_agents::analyst::grouping::refresh;
use traffic_rewrite_agents::analyst::grouping::{
    self, apply_submission, available, batch_id, selected_scope,
};

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

fn context_for_state(
    root: &Path,
    state: &RewriteState,
    loaded: &catalog::LoadedCatalog,
) -> Result<RepositoryAnalysisContext> {
    if let Some(pending) = state.case_pattern_identification.as_ref() {
        return case_pattern_batch::context(root, state, pending, loaded);
    }
    grouping::context(root, state, loaded)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) use traffic_rewrite_model::rewrite::repository_analysis::case_pattern_batch::CasePatternAnalysisCommit;
