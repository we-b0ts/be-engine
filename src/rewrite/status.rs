use anyhow::Result;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteInventoryReport, RewritePhase, RewriteStatusReport,
};
use super::store::{RewriteLockState, RewriteStore};
use super::{
    RewriteContext, action, fingerprint, inventory, process_outputs, revalidation,
    traffic_operation,
};
use crate::RecordingApi;

pub fn status_rewrite(context: RewriteContext) -> Result<RewriteStatusReport> {
    status_rewrite_for_api(context, None)
}

pub fn inventory_rewrite(context: RewriteContext) -> Result<RewriteInventoryReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?.load()?;
    Ok(match state {
        Some(mut state) => {
            inventory::initialize_legacy(&mut state);
            if !state.api_inventory.is_empty() {
                process_outputs::ensure_inventory_matches(&state, &project.process_outputs)?;
            }
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            process_outputs::defer_for_target_change(&mut state, &target_fingerprint);
            RewriteInventoryReport {
                schema_version: ACTION_SCHEMA_VERSION,
                initialized: true,
                workflow: Some(action::workflow_view(&state)),
                api_inventory: Some(inventory::details(&state)),
                process_output_inventory: Some(super::process_outputs::details(&state)),
            }
        }
        None => RewriteInventoryReport {
            schema_version: ACTION_SCHEMA_VERSION,
            initialized: false,
            workflow: None,
            api_inventory: None,
            process_output_inventory: None,
        },
    })
}

pub fn status_rewrite_for_api(
    context: RewriteContext,
    api: Option<&RecordingApi>,
) -> Result<RewriteStatusReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?.load()?;
    Ok(match state {
        Some(mut state) => {
            inventory::initialize_legacy(&mut state);
            if !state.api_inventory.is_empty() {
                process_outputs::ensure_inventory_matches(&state, &project.process_outputs)?;
            }
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            process_outputs::defer_for_target_change(&mut state, &target_fingerprint);
            if state.phase == RewritePhase::ComparisonRecordingRequired
                && state.target_fingerprint.as_deref() != Some(target_fingerprint.as_str())
            {
                state.phase = RewritePhase::ApiPending;
                state.e2e_current = false;
                state.comparison_current = false;
                state.comparison_run_id = None;
                state.comparison_rejection = None;
                state.active_issue = None;
                state.target_fingerprint = None;
            }
            let requested_api = api.map(ToString::to_string);
            let envelope = match traffic_operation::state(&target_root)? {
                traffic_operation::TrafficOperationState::Live(active)
                    if active.kind == traffic_operation::TrafficOperationKind::Replay
                        || active.kind == traffic_operation::TrafficOperationKind::Comparison
                        || requested_api.as_ref().is_some_and(|requested| {
                            active.api.as_deref() != Some(requested.as_str())
                        }) =>
                {
                    action::wait_envelope(&target_root, &state, requested_api, &active)
                }
                traffic_operation::TrafficOperationState::Stale(_) => {
                    action::recovery_required(&target_root)
                }
                traffic_operation::TrafficOperationState::Live(_) => {
                    projected_action(&target_root, &state, api)?
                }
                traffic_operation::TrafficOperationState::Absent => {
                    if let Some(requested) = requested_api.as_ref()
                        && requested != &state.api
                        && matches!(
                            state.phase,
                            RewritePhase::RecordingRequired
                                | RewritePhase::ComparisonRecordingRequired
                                | RewritePhase::SystemRepairRequired
                        )
                    {
                        action::api_selection_wait_envelope(&target_root, &state, requested.clone())
                    } else {
                        match RewriteStore::new(&target_root)?.lock_state()? {
                            RewriteLockState::Live => action::coordinator_wait_envelope(
                                &target_root,
                                &state,
                                requested_api,
                            ),
                            RewriteLockState::Stale => action::recovery_required(&target_root),
                            RewriteLockState::Absent => {
                                projected_action(&target_root, &state, api)?
                            }
                        }
                    }
                }
            };
            let scoped = inventory::scoped(&state, api).unwrap_or(state);
            RewriteStatusReport {
                schema_version: envelope.schema_version,
                initialized: true,
                workflow: envelope.workflow,
                api_inventory: envelope.api_inventory,
                process_output_inventory: envelope.process_output_inventory,
                latest_focused_e2e: envelope.latest_focused_e2e,
                e2e_current: scoped.e2e_current,
                comparison_current: scoped.comparison_current,
                terminal_allowed: envelope.terminal_allowed,
                action: envelope.action,
            }
        }
        None => {
            let envelope = match RewriteStore::new(&target_root)?.lock_state()? {
                RewriteLockState::Live => action::uninitialized_coordinator_wait_envelope(
                    &target_root,
                    api.map(ToString::to_string),
                ),
                RewriteLockState::Stale => action::recovery_required(&target_root),
                RewriteLockState::Absent => action::input_required(&target_root),
            };
            RewriteStatusReport {
                schema_version: envelope.schema_version,
                initialized: false,
                workflow: None,
                api_inventory: None,
                process_output_inventory: None,
                latest_focused_e2e: None,
                e2e_current: false,
                comparison_current: false,
                terminal_allowed: false,
                action: envelope.action,
            }
        }
    })
}

pub fn status_rewrite_for_process_output(
    context: RewriteContext,
    id: &str,
) -> Result<RewriteStatusReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?.load()?;
    Ok(match state {
        Some(mut state) => {
            inventory::initialize_legacy(&mut state);
            if !state.api_inventory.is_empty() {
                process_outputs::ensure_inventory_matches(&state, &project.process_outputs)?;
            }
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            process_outputs::defer_for_target_change(&mut state, &target_fingerprint);
            let scoped = process_outputs::scoped(&state, id)?;
            let mut envelope = match traffic_operation::state(&target_root)? {
                traffic_operation::TrafficOperationState::Live(active) => {
                    action::wait_envelope(&target_root, &scoped, None, &active)
                }
                traffic_operation::TrafficOperationState::Stale(_) => {
                    action::recovery_required(&target_root)
                }
                traffic_operation::TrafficOperationState::Absent => {
                    match RewriteStore::new(&target_root)?.lock_state()? {
                        RewriteLockState::Live => {
                            action::coordinator_wait_envelope(&target_root, &scoped, None)
                        }
                        RewriteLockState::Stale => action::recovery_required(&target_root),
                        RewriteLockState::Absent => action::for_status(&target_root, &scoped)?,
                    }
                }
            };
            action::retarget_wait_status_for_process_output(&mut envelope, &target_root, id);
            RewriteStatusReport {
                schema_version: envelope.schema_version,
                initialized: true,
                workflow: envelope.workflow,
                api_inventory: envelope.api_inventory,
                process_output_inventory: envelope.process_output_inventory,
                latest_focused_e2e: envelope.latest_focused_e2e,
                e2e_current: scoped.e2e_current,
                comparison_current: scoped.comparison_current,
                terminal_allowed: envelope.terminal_allowed,
                action: envelope.action,
            }
        }
        None => {
            let envelope = match RewriteStore::new(&target_root)?.lock_state()? {
                RewriteLockState::Live => {
                    action::uninitialized_coordinator_wait_envelope(&target_root, None)
                }
                RewriteLockState::Stale => action::recovery_required(&target_root),
                RewriteLockState::Absent => action::input_required(&target_root),
            };
            RewriteStatusReport {
                schema_version: envelope.schema_version,
                initialized: false,
                workflow: None,
                api_inventory: None,
                process_output_inventory: None,
                latest_focused_e2e: None,
                e2e_current: false,
                comparison_current: false,
                terminal_allowed: false,
                action: envelope.action,
            }
        }
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
    action::for_status(target_root, &scoped)
}
