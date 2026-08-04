use anyhow::Result;

use super::model::{RewritePhase, RewriteStatusReport};
use super::store::{RewriteLockState, RewriteStore};
use super::{RewriteContext, action, fingerprint, inventory, traffic_operation};
use crate::RecordingApi;

pub fn status_rewrite(context: RewriteContext) -> Result<RewriteStatusReport> {
    status_rewrite_for_api(context, None)
}

pub fn status_rewrite_for_api(
    context: RewriteContext,
    api: Option<&RecordingApi>,
) -> Result<RewriteStatusReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?.load()?;
    Ok(match state {
        Some(mut state) => {
            inventory::initialize_legacy(&mut state);
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            inventory::invalidate_completed_for_target_change(&mut state, &target_fingerprint)?;
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
                    let scoped = inventory::scoped(&state, api)?;
                    action::for_status(&target_root, &scoped)?
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
                                let scoped = inventory::scoped(&state, api)?;
                                action::for_status(&target_root, &scoped)?
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
                latest_focused_e2e: None,
                e2e_current: false,
                comparison_current: false,
                terminal_allowed: false,
                action: envelope.action,
            }
        }
    })
}
