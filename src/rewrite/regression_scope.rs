//! Reversible API exclusion at the coordinator inventory boundary. Saved slices and
//! verification evidence remain intact; skipped items are never verified items.
use std::path::Path;

use anyhow::{Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewritePhase, RewriteSliceState,
    RewriteState,
};
use super::{action, inventory};

use crate::config::regression as config;
pub(super) use config::PATH;
mod recording;
pub(super) use recording::{ensure_fresh_allowed, has_active_pin, validate_uninitialized};

pub(super) fn is_skipped(state: &RewriteState, api: &str) -> bool {
    state
        .api_inventory
        .iter()
        .any(|item| item.api == api && item.status == RewriteApiStatus::Skipped)
}

pub(super) fn has_skips(state: &RewriteState) -> bool {
    state
        .api_inventory
        .iter()
        .any(|item| item.status == RewriteApiStatus::Skipped)
}

pub(super) fn apply(target_root: &Path, state: &mut RewriteState) -> Result<bool> {
    let policy = config::RegressionScope::load(target_root)?;
    // A running deterministic traffic operation finishes before inputs change.
    if super::execution::owned_by_other_process(target_root)?
        || !matches!(
            super::traffic_operation::state(target_root)?,
            super::traffic_operation::TrafficOperationState::Absent
        )
    {
        return Ok(false);
    }
    let mut changed = recording::apply(target_root, state, &policy)?;
    if !state.api_inventory.is_empty() && state.phase != RewritePhase::RecordingRequired {
        for api in policy.selectors() {
            ensure!(
                state
                    .api_inventory
                    .iter()
                    .any(|item| crate::recording_api::identity(&item.api) == api),
                "{PATH}: API {api:?} is absent from the recorded inventory; use backend-rewrite inventory"
            );
        }
    }
    if state.api_inventory.is_empty() || state.phase == RewritePhase::RecordingRequired {
        if changed {
            state.bump();
        }
        return Ok(changed);
    }
    for item in &mut state.api_inventory {
        if policy.includes(&item.api) {
            if item.status == RewriteApiStatus::Skipped {
                item.status = state
                    .skipped_api_statuses
                    .remove(&item.api)
                    .unwrap_or(RewriteApiStatus::Pending);
                changed = true;
            }
        } else if item.status != RewriteApiStatus::Skipped {
            state
                .skipped_api_statuses
                .insert(item.api.clone(), item.status);
            item.status = RewriteApiStatus::Skipped;
            changed = true;
        }
    }
    inventory::revalidation_round::reconcile_skips(state);
    if is_skipped(state, &state.api) {
        let api = state.api.clone();
        state
            .parked_slices
            .insert(api.clone(), state.active_slice.clone());
        // Active is a selection, not a resumable parked status.
        if state.skipped_api_statuses.get(&api) == Some(&RewriteApiStatus::Active) {
            let status = match state.phase {
                RewritePhase::ImplementationRequired => RewriteApiStatus::ImplementationRequired,
                RewritePhase::SystemRepairRequired => RewriteApiStatus::SystemRepairRequired,
                RewritePhase::AwaitingRecordingRefresh => {
                    RewriteApiStatus::AwaitingRecordingRefresh
                }
                _ => RewriteApiStatus::Pending,
            };
            state.skipped_api_statuses.insert(api, status);
        }
        state.current_api_index = None;
        state.active_slice = RewriteSliceState::pending(String::new(), String::new());
        state.phase = RewritePhase::SliceComplete;
        changed = true;
    }
    if state.current_api_index.is_none() {
        let next = inventory::next_runnable_index(state).or_else(|| {
            state.api_inventory.iter().position(|item| {
                matches!(
                    item.status,
                    RewriteApiStatus::SystemRepairRequired
                        | RewriteApiStatus::AwaitingRecordingRefresh
                )
            })
        });
        if let Some(index) = next {
            inventory::resume_at(state, index)?;
            changed = true;
        }
    }
    if changed {
        state.bump();
    }
    Ok(changed)
}

pub(super) fn skipped_envelope(
    target_root: &Path,
    state: &RewriteState,
    api: &str,
) -> Option<RewriteActionEnvelope> {
    is_skipped(state, api).then(|| {
        let mut envelope = action::envelope(
            target_root,
            state,
            RewriteAction::Complete {
                summary: format!(
                    "{api} is skipped by {PATH}; no verification was performed for this scope"
                ),
                e2e_current: false,
            },
        );
        envelope.latest_focused_e2e = None;
        envelope
    })
}

#[cfg(test)]
mod tests;
