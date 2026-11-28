//! Explicit, authorized regression-round lifecycle. Session restarts never reset work.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{
    action, artifacts, case_patterns, execution, inventory,
    model::{
        ACTION_SCHEMA_VERSION, RewriteActionEnvelope, RewritePhase, RewriteSliceState, RewriteState,
    },
    regression_scope, source_diff,
    store::RewriteStore,
    traffic_operation, worker,
};

#[derive(Debug, Clone)]
pub struct RewriteRegressionBeginOptions {
    pub target_root: PathBuf,
    /// Attests explicit user authorization for this new round, never inferred from a session.
    pub caller_approved: bool,
    /// Require a newly published recording for this round.
    pub record_new_traffic: bool,
    /// Actual active child agent/session count in the caller's current runtime session.
    pub active_agent_count: usize,
    /// Query executed by that coordinator, not an engine-owned worker inventory count.
    pub runtime_query: super::RewriteWorkerMissingQuery,
}

pub use traffic_rewrite_model::rewrite::regression::RegressionOrigin;

#[derive(Debug, Serialize)]
pub struct RewriteRegressionBeginReport {
    pub schema_version: u32,
    pub previous_workflow_id: Option<String>,
    pub archive: Option<PathBuf>,
    pub work_branch: String,
    pub next: RewriteActionEnvelope,
}

pub fn begin(options: RewriteRegressionBeginOptions) -> Result<RewriteRegressionBeginReport> {
    ensure!(
        options.caller_approved,
        "starting a new regression requires explicit user authorization: --user-approved"
    );
    ensure!(
        options.active_agent_count == 0,
        "purpose confirmation requires zero active child agents/sessions in the coordinator's current runtime session; observed {}. Do not stop them automatically or use engine worker bindings as this count",
        options.active_agent_count
    );
    worker::validate_runtime_query(&options.runtime_query)?;
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
    let previous = store.load_for_replacement(options.record_new_traffic)?;
    let previous_state = previous.as_ref().and_then(|old| old.current());
    let mut state = match previous_state {
        Some(previous) => reset(previous.clone()),
        None => super::initialization::new_state(String::new(), String::new(), Vec::new()),
    };
    state.implementers = Some(super::implementer::ImplementerPool::new(
        super::implementer::ImplementerPool::DEFAULT_CAPACITY,
    ));
    state.repository_analysis = None;
    state.group_replay = None;
    state.last_group_replay = None;
    if !options.record_new_traffic {
        if state.recording_run_id.is_empty() {
            super::recording_input::bind(&target_root, &mut state, None)?;
        }
        ensure!(
            !state.recording_run_id.is_empty(),
            "select a completed standard recording or publish one with traffic-e2e record"
        );
        artifacts::validate_standard_recording(&target_root, &state)?;
        inventory::reset_for_recording(&mut state);
        state.active_slice = RewriteSliceState::pending(String::new(), String::new());
        state.phase = RewritePhase::RecordingRequired;
        if !case_patterns::identify_after_finalized_recording(&target_root, &mut state)? {
            let apis = artifacts::standard_recording_apis(&target_root, &state)?;
            inventory::install(&mut state, apis)?;
        }
    } else {
        let settings = state.recording_settings;
        super::recording::reset_for_fresh_recording(
            &target_root,
            &mut state,
            settings,
            super::model::RewriteRecordingReason::UserRequested,
        )?;
    }
    state.regression = Some(RegressionOrigin {
        previous_workflow_id: previous
            .as_ref()
            .map(|s| s.workflow_id().to_owned())
            .unwrap_or_default(),
        started_at: chrono::Utc::now().to_rfc3339(),
        pr_base: project.pr_base.clone(),
        base_revision: source_diff::git_text(&target_root, &["rev-parse", "HEAD"])?
            .trim()
            .into(),
        base_fingerprint: super::fingerprint::repository_fingerprint(&target_root)?,
        user_approved: true,
        runtime_query: None,
        record_new_traffic: options.record_new_traffic,
        active_session_agent_count: Some(options.active_agent_count),
        session_runtime_query: Some(options.runtime_query),
        superseded_recording_run_id: None,
    });
    regression_scope::apply(&target_root, &mut state)?;
    require_base(&target_root, &project.pr_base)?;
    let archive = previous
        .as_ref()
        .map(|old| store.archive(old, &state.workflow_id))
        .transpose()?;
    let work_branch = branch::next(&target_root, options.record_new_traffic)?;
    // Publish the isolated state before entering the branch. Concurrent status must
    // never observe a new work branch with old workers still eligible for dispatch.
    store.save_snapshot(&state, &feedback)?;
    if let Err(error) = source_diff::git_text(&target_root, &["switch", "-c", &work_branch]) {
        // A failing Git hook can report failure after switching. Keep the new
        // isolated state in that case; only restore old state while still on base.
        if super::purpose::base_branch(&target_root)?.is_some() {
            store.restore_snapshot(previous.as_ref(), &feedback)?;
        }
        return Err(error).context(
            "failed to enter the new purpose work branch; inspect status before retrying",
        );
    }
    execution::retire_finished(&target_root)?;
    let next = action::for_status(&target_root, &state)?;
    Ok(RewriteRegressionBeginReport {
        schema_version: ACTION_SCHEMA_VERSION,
        previous_workflow_id: previous.map(|s| s.workflow_id().to_owned()),
        archive,
        work_branch,
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
    // A new workflow grants each API one first binding. Once bound, ordinary
    // confirm/transfer rules prevent a second unapproved replacement.
    state.worker_bindings.clear();
    state.worker_event_revision = 0;
    state.source_review_rework.clear();
    state.target_quality_fingerprint = None;
    state.delivery_review_required = false;
    state.recording_rejection = None;
    state.recording_request_reason = None;
    state.recording_input_case_source = None;
    state.recording_input_diagnosis = None;
    state.case_pattern_identification = None;
    state.case_pattern_analysis = None;
    state.recording_refresh = None;
    state.revalidation_round = None;
    state.pre_revalidation_review = None;
    state.regression = None;
    state
}

mod branch;

#[cfg(test)]
mod tests;
