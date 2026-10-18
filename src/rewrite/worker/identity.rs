//! Resolve runtime handles without requiring coordinator-owned engine IDs.
use anyhow::{Context, Result, ensure};

use super::super::review::RewriteReviewReport;
use super::super::work_scope::RewriteWorkScope;
use super::super::{fingerprint, model::RewriteState};
use super::model::RewriteWorkerActivity;
use super::runtime::{self, RewriteWorkerReportOptions};

pub(super) fn scope_for_handle(state: &RewriteState, handle: &str) -> Result<RewriteWorkScope> {
    ensure!(
        state.implementers.is_none(),
        "pooled workflows do not resolve API ownership from a runtime handle"
    );
    resolve_handle(state, handle, false)
}

fn resolve_handle(
    state: &RewriteState,
    handle: &str,
    observe_rule_replay: bool,
) -> Result<RewriteWorkScope> {
    let fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", handle]);
    let mut scopes = runtime::scopes(state);
    if observe_rule_replay {
        // A rule can release worker delivery while its existing task is still
        // finishing. Accept runtime observations without redispatching that task.
        scopes.extend(
            std::iter::once(&state.active_slice)
                .chain(state.parked_slices.values())
                .map(|slice| super::super::api_selector::work_scope(state, &slice.api))
                .filter(|scope| {
                    super::super::rule_replay::ready(state, scope)
                        || super::super::replay_admission::admitted(state, scope)
                        || super::super::replay_admission::all_ready(state, scope, |slice| {
                            slice.engine_retry_running
                        })
                }),
        );
    }
    let mut unique = Vec::new();
    for scope in scopes {
        if !unique.contains(&scope) {
            unique.push(scope);
        }
    }
    let mut matches = unique.into_iter().filter(|scope| {
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
    let runtime_observation = matches!(
        options.activity,
        RewriteWorkerActivity::Running
            | RewriteWorkerActivity::Queued
            | RewriteWorkerActivity::Idle
    );
    let scope = if state.implementers.is_some() {
        ensure!(
            !runtime_observation && options.activity != RewriteWorkerActivity::HandoffReady,
            "pooled workflows require implementer report/handoff with explicit API, dispatch and lease generation"
        );
        let path = options
            .review_report
            .as_deref()
            .context("pool integration requires the exact original review report")?;
        let report: RewriteReviewReport = serde_json::from_slice(&std::fs::read(path)?)?;
        if let Some(scope) = report.scope {
            scope
        } else {
            let integration = report
                .integration
                .context("integration report has no API handoff identities")?;
            let mut entries = integration
                .handoffs
                .iter()
                .filter(|entry| Some(&entry.handoff_id) == options.handoff_id.as_ref());
            let entry = entries
                .next()
                .context("handoff id is absent from the integration report")?;
            ensure!(
                entries.next().is_none(),
                "handoff id identifies multiple API deliveries"
            );
            entry.scope.clone()
        }
    } else {
        resolve_handle(state, &options.agent_handle, runtime_observation)?
    };
    ensure!(
        runtime::scopes(state).contains(&scope) || state.implementers.is_none(),
        "integration scope has no current implementation dispatch"
    );
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
        let batch_entry = report.integration.as_ref().and_then(|integration| {
            integration
                .handoffs
                .iter()
                .find(|entry| entry.scope == scope && entry.dispatch_id == dispatch)
        });
        let matching_delivery = report.scope.as_ref() == Some(&scope)
            && report.dispatch_id.as_deref() == Some(dispatch.as_str());
        let matching_batch = matches!(
            options.activity,
            RewriteWorkerActivity::Integrated | RewriteWorkerActivity::ReworkRequired
        ) && report.scope.is_none()
            && report.dispatch_id.is_none()
            && report.schema_version == 3
            && report
                .integration
                .as_ref()
                .is_some_and(|integration| integration.handoff_id.is_none())
            && batch_entry.is_some_and(|entry| {
                Some(entry.handoff_id.as_str()) == options.handoff_id.as_deref()
            });
        ensure!(
            report.workflow_id == state.workflow_id
                && (matching_delivery || matching_batch)
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
