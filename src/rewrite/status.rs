use anyhow::Result;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteInventoryReport, RewritePhase, RewriteStatusReport,
};
use super::store::{RewriteLockState, RewriteStore};
use super::{RewriteContext, action, fingerprint, inventory, revalidation, traffic_operation};
use crate::RecordingApi;

pub fn status_rewrite(context: RewriteContext) -> Result<RewriteStatusReport> {
    status_rewrite_for_api(context, None)
}

pub fn inventory_rewrite(context: RewriteContext) -> Result<RewriteInventoryReport> {
    with_read_snapshot(|| inventory_rewrite_uncached(context))
}

fn inventory_rewrite_uncached(context: RewriteContext) -> Result<RewriteInventoryReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    if super::purpose::pending(&target_root)?.is_some() {
        return Ok(RewriteInventoryReport {
            implementers: None,
            repository_analysis: None,
            group_replay: None,
            last_group_replay: None,
            schema_version: ACTION_SCHEMA_VERSION,
            initialized: RewriteStore::new(&target_root)?.exists(),
            workflow: None,
            api_inventory: None,
            pending: 1,
            details: super::coordination::single_ready("confirm_purpose", 1),
            workers: Vec::new(),
            experts: Vec::new(),
        });
    }
    let state = RewriteStore::new(&target_root)?.load()?;
    Ok(match state {
        Some(mut state) => {
            inventory::initialize_legacy(&mut state);
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            let details = if let Some(report) = super::configuration_commit::status(&target_root)?
                && !matches!(report.action, super::RewriteAction::ExpertRequired { .. })
            {
                super::coordination::single_ready("commit_configuration", report.pending)
            } else {
                super::coordination::status_details(&target_root, &state)?
            };
            RewriteInventoryReport {
                implementers: super::implementer::view(&target_root, &state)?,
                repository_analysis: state.repository_analysis.clone(),
                group_replay: state.group_replay.clone(),
                last_group_replay: state.last_group_replay.clone(),
                schema_version: ACTION_SCHEMA_VERSION,
                initialized: true,
                workflow: Some(action::workflow_view(&state)),
                api_inventory: Some(inventory::details(&state)),
                pending: details.pending(),
                details,
                workers: super::worker::scheduler::inventory(&target_root, &state),
                experts: super::expert::inventory(&target_root, &state),
            }
        }
        None => {
            let pending = status_rewrite(context)?.pending;
            RewriteInventoryReport {
                implementers: None,
                repository_analysis: None,
                group_replay: None,
                last_group_replay: None,
                schema_version: ACTION_SCHEMA_VERSION,
                initialized: false,
                workflow: None,
                api_inventory: None,
                pending,
                details: super::coordination::initial_details(pending),
                workers: Vec::new(),
                experts: Vec::new(),
            }
        }
    })
}

pub fn status_rewrite_for_api(
    context: RewriteContext,
    api: Option<&RecordingApi>,
) -> Result<RewriteStatusReport> {
    with_read_snapshot(|| status_rewrite_for_api_uncached(context, api))
}

fn status_rewrite_for_api_uncached(
    context: RewriteContext,
    api: Option<&RecordingApi>,
) -> Result<RewriteStatusReport> {
    if let Some(report) = super::purpose::status(&context.target_root)? {
        return Ok(report);
    }
    if let Some(report) = super::configuration_commit::status(&context.target_root)? {
        return Ok(report);
    }
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?.load()?;
    Ok(match state {
        Some(mut state) => {
            inventory::initialize_legacy(&mut state);
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            let pending = super::coordination::status_details(&target_root, &state)?.pending();
            let envelope = api_envelope(&target_root, &state, api)?;
            let skipped = api
                .is_some_and(|api| super::regression_scope::is_skipped(&state, &api.to_string()));
            let scoped = inventory::scoped(&state, api).unwrap_or(state);
            RewriteStatusReport {
                schema_version: envelope.schema_version,
                pending,
                initialized: true,
                workflow: envelope.workflow,
                api_inventory: envelope.api_inventory,
                latest_focused_e2e: envelope.latest_focused_e2e,
                e2e_current: !skipped && scoped.e2e_current,
                terminal_allowed: envelope.terminal_allowed,
                action: envelope.action,
            }
        }
        None => {
            let mut envelope = match RewriteStore::new(&target_root)?.lock_state()? {
                RewriteLockState::Live => action::uninitialized_coordinator_wait_envelope(
                    &target_root,
                    api.map(ToString::to_string),
                ),
                RewriteLockState::Stale => action::recovery_required(&target_root),
                RewriteLockState::Absent => action::input_required(&target_root),
            };
            if let Some(selected) = super::execution::status_action(&target_root)? {
                envelope.pending = usize::from(matches!(
                    selected,
                    super::RewriteAction::RecoveryRequired { .. }
                        | super::RewriteAction::WaitRequired { .. }
                ));
                envelope.action = selected;
            }
            RewriteStatusReport {
                schema_version: envelope.schema_version,
                pending: envelope.pending,
                initialized: false,
                workflow: None,
                api_inventory: None,
                latest_focused_e2e: None,
                e2e_current: false,
                terminal_allowed: false,
                action: envelope.action,
            }
        }
    })
}

fn with_read_snapshot<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    crate::repository::with_git_root_cache(|| {
        crate::e2e_run::with_project_resolution_cache(|| {
            crate::e2e_run::with_background_reclassification_snapshot(|| {
                super::source_diff::with_git_read_cache(|| {
                    fingerprint::with_repository_cache(operation)
                })
            })
        })
    })
}

fn projected_action(
    target_root: &std::path::Path,
    state: &super::model::RewriteState,
    api: Option<&RecordingApi>,
) -> Result<super::model::RewriteActionEnvelope> {
    if let Some(api) = api
        && let Some(envelope) = revalidation::deferred_status_envelope(target_root, state, api)?
    {
        return Ok(envelope);
    }
    let scoped = inventory::scoped(state, api)?;
    if api.is_some() {
        action::for_scoped_status(target_root, &scoped)
    } else {
        action::for_status(target_root, &scoped)
    }
}

fn api_envelope(
    target_root: &std::path::Path,
    state: &super::model::RewriteState,
    api: Option<&RecordingApi>,
) -> Result<super::model::RewriteActionEnvelope> {
    let mut envelope = api_envelope_unannotated(target_root, state, api)?;
    super::execution::annotate_status(target_root, &mut envelope.action)?;
    Ok(envelope)
}

fn api_envelope_unannotated(
    target_root: &std::path::Path,
    state: &super::model::RewriteState,
    api: Option<&RecordingApi>,
) -> Result<super::model::RewriteActionEnvelope> {
    if let Some(plan) = super::rule_plans::idle_action(target_root, state)? {
        return Ok(action::envelope(target_root, state, plan));
    }
    if let Some(analysis) = super::repository_analysis::required_action(target_root, state)? {
        return Ok(action::envelope(target_root, state, analysis));
    }
    if let Some(api) = api
        && let Some(envelope) =
            super::regression_scope::skipped_envelope(target_root, state, &api.to_string())
    {
        return Ok(envelope);
    }
    if let Some(api) = api
        && let Some(envelope) = revalidation::deferred_status_envelope(target_root, state, api)?
    {
        return Ok(envelope);
    }
    if state.revalidation_round.is_none()
        && state.group_replay.is_none()
        && let Some(expert) = super::expert::required_action(
            target_root,
            state,
            api.map(ToString::to_string).as_deref(),
        )
    {
        return Ok(action::envelope(target_root, state, expert));
    }
    // Inspecting a parked worker does not activate that API. Dispatch and status
    // feedback stay available while another API is at a system-repair gate.
    if api.is_some()
        && state.group_replay.is_none()
        && let Some(envelope) = super::coordination::busy_workers(target_root, state, api)?
    {
        return Ok(envelope);
    }
    let requested_api = api.map(ToString::to_string);
    let envelope = if super::coordination::resources_busy(target_root)? {
        if let Some(envelope) = super::coordination::busy_workers(target_root, state, api)? {
            Some(envelope)
        } else {
            super::execution::status_action(target_root)?
                .map(|selected| action::envelope(target_root, state, selected))
        }
    } else if let Some(failed) = super::execution::status_action(target_root)? {
        let worker = if let Some(api) = api {
            let scope = super::RewriteWorkScope::Api {
                api: api.to_string(),
            };
            super::worker::runtime::scopes(state)
                .contains(&scope)
                .then(|| super::worker::scheduler::scope_action(target_root, state, &scope))
                .filter(|_| {
                    super::worker::runtime::coverage(state, &scope)
                        != super::worker::model::RewriteWorkerCoverageState::Running
                })
        } else {
            super::worker::scheduler::global_action(target_root, state, false)
        }
        .filter(|action| !matches!(action, super::RewriteAction::AdvanceRequired { .. }));
        Some(action::envelope(
            target_root,
            state,
            worker.unwrap_or(failed),
        ))
    } else {
        None
    };
    let envelope = if let Some(envelope) = envelope {
        envelope
    } else {
        match traffic_operation::state(target_root)? {
            traffic_operation::TrafficOperationState::Live(active)
                if active.kind == traffic_operation::TrafficOperationKind::Replay
                    || requested_api.as_ref().is_some_and(|requested| {
                        active.api.as_deref() != Some(requested.as_str())
                    }) =>
            {
                action::wait_envelope(target_root, state, requested_api, &active)
            }
            traffic_operation::TrafficOperationState::Stale(_) => {
                action::recovery_required(target_root)
            }
            traffic_operation::TrafficOperationState::Live(_) => {
                projected_action(target_root, state, api)?
            }
            traffic_operation::TrafficOperationState::Absent => {
                if let Some(requested) = requested_api.as_ref()
                    && requested != &state.api
                    && matches!(state.phase, RewritePhase::RecordingRequired)
                {
                    action::api_selection_wait_envelope(target_root, state, requested.clone())
                } else {
                    match RewriteStore::new(target_root)?.lock_state()? {
                        RewriteLockState::Live => {
                            action::coordinator_wait_envelope(target_root, state, requested_api)
                        }
                        RewriteLockState::Stale => action::recovery_required(target_root),
                        RewriteLockState::Absent => projected_action(target_root, state, api)?,
                    }
                }
            }
        }
    };
    Ok(envelope)
}
