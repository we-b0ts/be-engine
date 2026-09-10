//! Resolve runtime handles without requiring coordinator-owned engine IDs.
use anyhow::{Context, Result, ensure};

use super::super::process_output_model::RewriteWorkScope;
use super::super::review::RewriteReviewReport;
use super::super::{fingerprint, model::RewriteState};
use super::model::RewriteWorkerActivity;
use super::runtime::{self, RewriteWorkerReportOptions};

pub(super) fn scope_for_handle(state: &RewriteState, handle: &str) -> Result<RewriteWorkScope> {
    let fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", handle]);
    let mut matches = runtime::scopes(state).into_iter().filter(|scope| {
        state
            .worker_bindings
            .get(&scope.binding_key())
            .is_some_and(|binding| binding.agent_handle_fingerprint == fingerprint)
    });
    let scope = matches.next().context(
        "subagent handle has no outstanding worker binding; inspect backend-rewrite inventory",
    )?;
    ensure!(
        matches.next().is_none(),
        "subagent handle has ambiguous worker bindings"
    );
    Ok(scope)
}

pub(super) fn report_scope(
    state: &RewriteState,
    options: &RewriteWorkerReportOptions,
) -> Result<RewriteWorkScope> {
    let scope = scope_for_handle(state, &options.agent_handle)?;
    let dispatch = super::dispatch_id(state, &scope);
    let binding = &state.worker_bindings[&scope.binding_key()];
    ensure!(
        binding.confirmed_dispatch_id == dispatch,
        "worker report requires confirmation of the current dispatch"
    );
    if matches!(
        options.activity,
        RewriteWorkerActivity::Running
            | RewriteWorkerActivity::Queued
            | RewriteWorkerActivity::Idle
    ) {
        ensure!(
            options.review_report.is_none(),
            "runtime observations do not accept a review report; report a fresh task-runtime query"
        );
    } else {
        let path = options.review_report.as_deref().context(
            "handoff_ready, integrated and rework_required require --review-report with the original dispatch; resume an incomplete delivery as idle",
        )?;
        let bytes = std::fs::read(path)
            .with_context(|| format!("cannot read review document {}", path.display()))?;
        let report: RewriteReviewReport = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid review document {}", path.display()))?;
        ensure!(
            report.workflow_id == state.workflow_id
                && report.scope.as_ref() == Some(&scope)
                && report.dispatch_id.as_deref() == Some(dispatch.as_str())
                && report.validation.as_ref().is_some_and(|validation| {
                    validation.recording_run_id == state.recording_run_id
                }),
            "review report belongs to another workflow, recording, worker or stale dispatch"
        );
    }
    Ok(scope)
}

pub(super) fn command_handle(argv: &mut Vec<String>, env: &mut Vec<String>, handle: Option<&str>) {
    if let Some(handle) = handle {
        argv.extend(["--agent-handle".into(), handle.into()]);
    } else {
        env.push(super::AGENT_HANDLE_ENV.into());
    }
}
