//! Command contracts for the original worker interface to an implementer.
use super::{
    binding::dispatch_id,
    feedback::{RewriteWorkerReportOptions, observation},
};
use crate::runtime_identity::{validate_identity, validate_runtime_query};
use anyhow::{Context, Result, ensure};
use traffic_rewrite_model::rewrite::{
    RewriteReviewReport, RewriteState, RewriteWorkScope, RewriteWorkerActivity,
    RewriteWorkerMissingQuery, RewriteWorkerTransferAuthorization,
};

#[derive(Debug, Clone)]
pub struct RewriteWorkerConfirmOptions {
    pub target_root: std::path::PathBuf,
    pub work_scope: RewriteWorkScope,
    pub worktree: Option<std::path::PathBuf>,
    pub agent_handle: String,
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteWorkerTransferOptions {
    pub target_root: std::path::PathBuf,
    pub previous_agent_handle: String,
    pub agent_handle: String,
    pub agent_name: Option<String>,
    pub reason: String,
    pub caller_approved: bool,
    /// Attests that an actual query confirmed the previous worker no longer exists.
    pub runtime_query: Option<RewriteWorkerMissingQuery>,
}

pub const AGENT_HANDLE_ENV: &str = "BACKEND_REWRITE_SUBAGENT_HANDLE";

pub fn validate_confirmation(options: &RewriteWorkerConfirmOptions) -> Result<()> {
    validate_identity("subagent handle", &options.agent_handle, 4_096)?;
    if let Some(name) = options.agent_name.as_deref() {
        validate_identity("subagent name", name, 128)?;
    }
    Ok(())
}

pub fn validate_transfer(
    options: &RewriteWorkerTransferOptions,
) -> Result<RewriteWorkerTransferAuthorization> {
    validate_identity("subagent handle", &options.agent_handle, 4_096)?;
    validate_identity(
        "previous subagent handle",
        &options.previous_agent_handle,
        4_096,
    )?;
    validate_identity("ownership transfer reason", &options.reason, 512)?;
    if let Some(name) = options.agent_name.as_deref() {
        validate_identity("subagent name", name, 128)?;
    }
    transfer_authorization(options.caller_approved, options.runtime_query.as_ref())
}

fn transfer_authorization(
    caller_approved: bool,
    runtime_query: Option<&RewriteWorkerMissingQuery>,
) -> Result<RewriteWorkerTransferAuthorization> {
    ensure!(
        !(caller_approved && runtime_query.is_some()),
        "provide only one worker transfer authorization: explicit user approval or runtime query command/time"
    );
    if caller_approved {
        return Ok(RewriteWorkerTransferAuthorization::UserApproved);
    }
    let query = runtime_query.context(
        "worker ownership transfer requires explicit user approval or runtime_api_confirmed_missing: supply the API/command actually queried and its query time",
    )?;
    validate_runtime_query(query)?;
    Ok(
        RewriteWorkerTransferAuthorization::RuntimeApiConfirmedMissing {
            query: query.clone(),
        },
    )
}

pub fn resolve_handle(
    state: &RewriteState,
    handle: &str,
    scopes: impl IntoIterator<Item = RewriteWorkScope>,
) -> Result<RewriteWorkScope> {
    let fingerprint = crate::fingerprint::id(&["rewrite-subagent-handle-v1", handle]);
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

pub fn command_handle(argv: &mut Vec<String>, env: &mut Vec<String>, handle: Option<&str>) {
    if let Some(handle) = handle {
        argv.extend(["--agent-handle".into(), handle.into()]);
    } else {
        env.push(AGENT_HANDLE_ENV.into());
    }
}

pub fn report_scope(
    state: &RewriteState,
    options: &RewriteWorkerReportOptions,
    active_scopes: Vec<RewriteWorkScope>,
    observation_scopes: impl FnOnce() -> Vec<RewriteWorkScope>,
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
        if let Some(path) = options.review_report.as_deref() {
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
            let handoff = options
                .handoff_id
                .as_deref()
                .context("integration requires a handoff id")?;
            let mut scopes = active_scopes.iter().cloned().filter(|scope| {
                observation(state, scope).is_some_and(|o| o.handoff_id.as_deref() == Some(handoff))
            });
            let scope = scopes
                .next()
                .context("handoff has no current implementation dispatch")?;
            ensure!(
                scopes.next().is_none(),
                "handoff identifies multiple API deliveries"
            );
            scope
        }
    } else {
        let scopes = if runtime_observation {
            observation_scopes()
        } else {
            active_scopes.clone()
        };
        resolve_handle(state, &options.agent_handle, scopes)?
    };
    ensure!(
        active_scopes.contains(&scope) || state.implementers.is_none(),
        "integration scope has no current implementation dispatch"
    );
    let dispatch = dispatch_id(state, &scope);
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
            options.review_report.is_none() && options.delivery_commit.is_none(),
            "runtime observations do not accept a review report; report a fresh task-runtime query"
        );
    } else if let Some(path) = options.review_report.as_deref() {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_attestation_accepts_runtime_interfaces_and_timezone_formats() {
        for (command, time) in [
            ("ListAgents", "2026-09-12T04:00:00Z"),
            ("/list-agents", "2026-09-12T12:00:00+08:00"),
            ("runtime.get_agent", "2026-09-12T04:00:00.123Z"),
        ] {
            let query = RewriteWorkerMissingQuery {
                api_or_command: command.into(),
                queried_at: time.into(),
            };
            let authorization = transfer_authorization(false, Some(&query)).unwrap();
            assert_eq!(
                authorization,
                RewriteWorkerTransferAuthorization::RuntimeApiConfirmedMissing { query }
            );
        }
    }
}
