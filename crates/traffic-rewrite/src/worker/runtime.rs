use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::Utc;

use super::super::model::{RewriteActionEnvelope, RewritePhase, RewriteState};
use super::super::work_scope::RewriteWorkScope;
use super::super::{action, fingerprint, store::RewriteStore};
#[cfg(any(test, feature = "test-support"))]
use super::model::RewriteWorkerObservation;
use super::model::{RewriteWorkerActivity, RewriteWorkerCoverageState};
use traffic_rewrite_agents::implementer::legacy;

pub(crate) const ACTIVITY_ENV: &str = "BACKEND_REWRITE_WORKER_ACTIVITY";
pub(crate) const HANDOFF_ENV: &str = "BACKEND_REWRITE_WORKER_HANDOFF_ID";

pub use traffic_rewrite_agents::implementer::feedback::RewriteWorkerReportOptions;
pub(crate) use traffic_rewrite_agents::implementer::feedback::{
    apply_report, coverage, observation,
};
pub fn report(options: RewriteWorkerReportOptions) -> Result<RewriteActionEnvelope> {
    ensure!(
        options.delivery_commit.is_none() || options.review_report.is_none(),
        "supply delivery_commit or an existing receipt, not both"
    );
    crate::purpose::require_work_branch(&options.target_root)?;
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    super::validate_identity("subagent handle", &options.agent_handle, 4096)?;
    let store = RewriteStore::new(&target_root)?;
    let integration_lock = if matches!(
        options.activity,
        RewriteWorkerActivity::Integrated | RewriteWorkerActivity::ReworkRequired
    ) {
        let lock = store.try_lock()?.context(
            "integration must wait for the current verification or coordinator transition",
        )?;
        ensure!(
            matches!(
                super::super::traffic_operation::state(&target_root)?,
                super::super::traffic_operation::TrafficOperationState::Absent
            ),
            "integration must wait for the current traffic operation"
        );
        Some(lock)
    } else {
        None
    };
    let _lock = super::events::lock(&target_root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scope = super::identity::report_scope(&state, &options)?;
    let target_fingerprint = (options.activity == RewriteWorkerActivity::Integrated)
        .then(|| fingerprint::repository_fingerprint(&target_root))
        .transpose()?;
    let review = if options.activity == RewriteWorkerActivity::HandoffReady {
        let duplicate = observation(&state, &scope).is_some_and(|o| {
            o.handoff_id == options.handoff_id
                && matches!(
                    o.activity,
                    RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
                )
        });
        if duplicate {
            None
        } else {
            Some(if let Some(commit) = options.delivery_commit.as_deref() {
                super::super::review::delivery::worker(&target_root, &state, &scope, commit)?
            } else {
                super::super::review::accept_handoff(
                    &target_root,
                    &state,
                    &scope,
                    options.review_report.as_deref(),
                )?
            })
        }
    } else {
        None
    };
    let mut changed = apply_report(&mut state, &scope, &options, target_fingerprint)?;
    let integration_received = changed && options.activity == RewriteWorkerActivity::Integrated;
    if integration_received {
        let code_commit = if let Some(commit) = options.delivery_commit.as_deref() {
            super::super::review::delivery::integrate(
                &target_root,
                &mut state,
                &scope,
                options
                    .handoff_id
                    .as_deref()
                    .context("integration requires a handoff id")?,
                commit,
            )?
        } else {
            let path = options.review_report.as_deref().context(
                "integrated delivery requires --delivery-commit with the exact published commit",
            )?;
            super::super::review::accept_integration(
                &target_root,
                &mut state,
                path,
                Some(&scope),
                options.handoff_id.as_deref(),
            )?
        };
        if let Some(commit) = code_commit {
            let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
            if binding.last_integrated_commit.as_ref() != Some(&commit) {
                binding.last_integrated_commit = Some(commit);
                binding.last_integrated_at = Some(Utc::now().to_rfc3339());
            }
        }
    }

    if let Some(review) = review {
        state
            .worker_bindings
            .get_mut(&scope.binding_key())
            .unwrap()
            .review_report = Some(review);
    }
    let rework_finished = changed
        && options.activity == RewriteWorkerActivity::Integrated
        && state
            .source_review_rework
            .remove(&scope.binding_key())
            .is_some();
    if rework_finished {
        state.bump();
    }
    let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
    if binding.agent_handle.as_deref() != Some(&options.agent_handle) {
        binding.agent_handle = Some(options.agent_handle.clone());
        changed = true;
    }
    if changed {
        super::events::publish(&target_root, &state, &scope)?;
    }
    // A worker report never activates a slice or starts a traffic operation.
    // Recover the global action through status, which also honors live leases.
    drop(_lock);
    if rework_finished || integration_received {
        // Integration holds the coordinator lock. Save only after releasing the
        // feedback lock, because save folds in newer worker observations itself.
        store.save(&state)?;
    }
    drop(integration_lock);
    current_envelope(&target_root)
}

pub(crate) fn current_envelope(target_root: &Path) -> Result<RewriteActionEnvelope> {
    let status = super::super::status_rewrite(super::super::RewriteContext {
        target_root: target_root.to_path_buf(),
    })?;
    Ok(RewriteActionEnvelope {
        schema_version: status.schema_version,
        pending: status.pending,
        workflow: status.workflow,
        api_inventory: status.api_inventory,
        latest_focused_e2e: status.latest_focused_e2e,
        action: status.action,
        terminal_allowed: status.terminal_allowed,
    })
}

pub(crate) fn scopes(state: &RewriteState) -> Vec<RewriteWorkScope> {
    let mut scopes = Vec::new();
    if !super::super::regression_scope::is_skipped(state, &state.api)
        && state.phase == RewritePhase::ImplementationRequired
        && state.active_issue.is_some()
        && !super::super::replay_admission::slice_ready(state, &state.active_slice)
        && !state.engine_retry_running
    {
        scopes.push(super::super::api_selector::work_scope(state, &state.api));
    }
    for (api, slice) in &state.parked_slices {
        if !super::super::regression_scope::is_skipped(state, api)
            && api != &state.api
            && slice.phase == RewritePhase::ImplementationRequired
            && slice.active_issue.is_some()
            && !super::super::replay_admission::slice_ready(state, slice)
            && !slice.engine_retry_running
        {
            let scope = super::super::api_selector::work_scope(state, api);
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
    }
    scopes
}

pub(crate) fn scoped(state: &RewriteState, scope: &RewriteWorkScope) -> Result<RewriteState> {
    match scope {
        RewriteWorkScope::Api { api } => {
            let selected = super::super::api_selector::scoped(state, api)?;
            Ok(selected)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn record_running_for_test(state: &mut RewriteState, scope: &RewriteWorkScope) {
    let observation = RewriteWorkerObservation {
        dispatch_id: super::dispatch_id(state, scope),
        recording_run_id: state.recording_run_id.clone(),
        activity: RewriteWorkerActivity::Running,
        observed_at: Utc::now().to_rfc3339(),
        coordinator_reported: true,
        handoff_id: None,
        integrated_target_fingerprint: None,
    };
    state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation = Some(observation);
}

pub(crate) fn acceptance_ready(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    let RewriteWorkScope::Api { api } = scope;
    if super::super::replay_admission::applying_policy(state)
        || std::iter::once(&state.active_slice)
            .chain(state.parked_slices.values())
            .any(|slice| {
                (slice.api == *api || super::super::api_selector::public_api(&slice.api) == api)
                    && super::super::replay_admission::pending_transaction(slice)
            })
    {
        return false;
    }
    super::super::replay_admission::admitted(state, scope)
        || (super::issue_for_scope(state, scope).is_some()
            && coverage(state, scope) == RewriteWorkerCoverageState::VerificationRequired)
}

pub(crate) fn report_command(
    target_root: &Path,
    agent_handle: Option<&str>,
    integrated: bool,
) -> super::super::model::RewriteCommandSpec {
    report_command_with_activity(
        target_root,
        agent_handle,
        integrated.then_some("integrated"),
    )
}

fn report_command_with_activity(
    target_root: &Path,
    agent_handle: Option<&str>,
    activity: Option<&str>,
) -> super::super::model::RewriteCommandSpec {
    let mut argv = vec!["worker".to_string(), "report".to_string()];
    let mut env = Vec::new();
    legacy::command_handle(&mut argv, &mut env, agent_handle);
    if let Some(activity) = activity {
        argv.extend(["--activity".to_string(), activity.to_string()]);
        env.push(HANDOFF_ENV.to_string());
        if activity != "rework_required" {
            env.push("BACKEND_REWRITE_DELIVERY_COMMIT".to_string());
        }
    } else {
        env.push(ACTIVITY_ENV.to_string());
    }
    action::command(target_root, argv, env)
}

pub(crate) fn rework_command_for_scope(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> super::super::model::RewriteCommandSpec {
    let handle = state
        .worker_bindings
        .get(&scope.binding_key())
        .and_then(|binding| binding.agent_handle.as_deref());
    report_command_with_activity(root, handle, Some("rework_required"))
}

pub(crate) fn report_command_for_scope(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
    integrated: bool,
) -> super::super::model::RewriteCommandSpec {
    let handle = state
        .worker_bindings
        .get(&scope.binding_key())
        .and_then(|binding| binding.agent_handle.as_deref());
    if !integrated && let Some(pool) = &state.implementers {
        if let Some((&slot_id, slot, task)) = pool.slots.iter().find_map(|(id, slot)| {
            slot.tasks
                .get(&scope.binding_key())
                .map(|task| (id, slot, task))
        }) {
            let mut argv = vec![
                "implementer".into(),
                "report".into(),
                "--slot".into(),
                slot_id.to_string(),
                "--api".into(),
                task.api.clone(),
                "--dispatch-id".into(),
                task.dispatch_id.clone(),
                "--lease-generation".into(),
                task.lease_generation.to_string(),
            ];
            let mut env = vec![ACTIVITY_ENV.into()];
            legacy::command_handle(&mut argv, &mut env, slot.agent_handle.as_deref());
            return action::command(root, argv, env);
        }
        if !observation(state, scope).is_some_and(|value| {
            matches!(
                value.activity,
                RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
            )
        }) {
            return action::status_command_for_api(root, Some(&scope.binding_key()));
        }
    }
    report_command(root, handle, integrated || state.implementers.is_some())
}

#[cfg(test)]
mod tests;
