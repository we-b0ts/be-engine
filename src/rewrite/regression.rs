//! Explicit, authorized regression-round lifecycle. Session restarts never reset work.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    RewriteWorkerMissingQuery, action, artifacts, execution, inventory,
    model::{ACTION_SCHEMA_VERSION, RewriteActionEnvelope, RewriteState},
    process_outputs, regression_scope, source_diff,
    store::RewriteStore,
    traffic_operation, worker,
};

#[derive(Debug, Clone)]
pub struct RewriteRegressionBeginOptions {
    pub target_root: PathBuf,
    /// Attests explicit user authorization for this new round, never inferred from a session.
    pub caller_approved: bool,
    /// Actual query confirming all previous workers/experts are stopped or absent.
    pub runtime_query: Option<RewriteWorkerMissingQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RegressionOrigin {
    pub previous_workflow_id: String,
    pub started_at: String,
    pub pr_base: String,
    pub base_revision: String,
    pub base_fingerprint: String,
    pub user_approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_query: Option<RewriteWorkerMissingQuery>,
}

#[derive(Debug, Serialize)]
pub struct RewriteRegressionBeginReport {
    pub schema_version: u32,
    pub previous_workflow_id: String,
    pub archive: PathBuf,
    pub next: RewriteActionEnvelope,
}

pub fn begin(options: RewriteRegressionBeginOptions) -> Result<RewriteRegressionBeginReport> {
    ensure!(
        options.caller_approved,
        "starting a new regression requires explicit user authorization: --approve-new-regression"
    );
    if let Some(query) = &options.runtime_query {
        worker::validate_runtime_query(query)?;
    }
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    require_base(&target_root, &project.pr_base)?;
    let store = RewriteStore::new(&target_root)?;
    let _coordinator = store.lock()?;
    ensure!(
        !execution::busy(&target_root)?,
        "finish or recover the previous coordinator operation before regression begin"
    );
    ensure!(
        matches!(
            traffic_operation::state(&target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "finish or recover the previous traffic operation before regression begin"
    );
    // Feedback cannot arrive between the archived snapshot and workflow replacement.
    let feedback = worker::events::lock(&target_root)?;
    let previous = store.load()?.context(
        "rewrite workflow is not initialized; initialize and complete a standard recording first",
    )?;
    ensure!(
        previous.recording_refresh.is_none(),
        "complete the pending recording refresh before regression begin"
    );
    ensure!(
        previous.worker_bindings.is_empty() || options.runtime_query.is_some(),
        "query the actual task runtime and stop all previous workers and experts before regression begin; supply --runtime-query-command and --runtime-query-at confirming they are stopped or absent (including skipped work items)"
    );
    artifacts::validate_standard_recording(&target_root, &previous)?;
    let apis = artifacts::standard_recording_apis(&target_root, &previous)?;
    let mut state = reset(previous.clone());
    state.regression = Some(RegressionOrigin {
        previous_workflow_id: previous.workflow_id.clone(),
        started_at: chrono::Utc::now().to_rfc3339(),
        pr_base: project.pr_base.clone(),
        base_revision: source_diff::git_text(&target_root, &["rev-parse", "HEAD"])?
            .trim()
            .into(),
        base_fingerprint: super::fingerprint::repository_fingerprint(&target_root)?,
        user_approved: true,
        runtime_query: options.runtime_query,
    });
    inventory::install(&mut state, apis)?;
    process_outputs::install(&mut state, &project.process_outputs);
    regression_scope::apply(&target_root, &mut state)?;
    let next = action::for_status(&target_root, &state)?;
    require_base(&target_root, &project.pr_base)?;
    let archive = store.archive(&previous, &state.workflow_id)?;
    store.save_snapshot(&state, &feedback)?;
    execution::retire_finished(&target_root)?;
    Ok(RewriteRegressionBeginReport {
        schema_version: ACTION_SCHEMA_VERSION,
        previous_workflow_id: previous.workflow_id,
        archive,
        next,
    })
}

fn require_base(target_root: &Path, pr_base: &str) -> Result<()> {
    let branch =
        source_diff::git_text(target_root, &["symbolic-ref", "--quiet", "--short", "HEAD"])
            .context(
                "regression begin requires the named pr_base branch; detached HEAD is not allowed",
            )?;
    ensure!(
        branch.trim() == pr_base,
        "regression begin requires current branch {pr_base:?}; found {:?}; equal commits on a feature branch do not qualify",
        branch.trim()
    );
    Ok(())
}

fn reset(mut state: RewriteState) -> RewriteState {
    state.workflow_id = format!("rewrite-{}", uuid::Uuid::new_v4().simple());
    state.revision = 1;
    state.worker_bindings.clear();
    state.worker_event_revision = 0;
    state.source_review_rework.clear();
    state.target_quality_fingerprint = None;
    state.delivery_review_required = true;
    state.recording_rejection = None;
    state.recording_request_reason = None;
    state.recording_input_case_source = None;
    state.recording_input_diagnosis = None;
    state.case_pattern_identification = None;
    state
}

/// Base Replay stays bound to authorized source/configuration, including startup inputs.
/// Engine progress commits do not change that identity; code repairs require a feature branch.
pub(crate) fn allows_base_replay(target_root: &Path, pr_base: &str) -> Result<bool> {
    let Some(state) = RewriteStore::new(target_root)?.load()? else {
        return Ok(false);
    };
    let Some(origin) = state.regression else {
        return Ok(false);
    };
    Ok(origin.user_approved
        && origin.pr_base == pr_base
        && super::fingerprint::repository_fingerprint(target_root)? == origin.base_fingerprint)
}

#[cfg(test)]
mod tests;
