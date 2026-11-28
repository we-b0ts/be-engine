//! Preserve recorded Case selections and resume a runnable slice after inventory changes.
use std::path::Path;

use anyhow::Result;

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewritePhase, RewriteSliceState,
    RewriteState,
};
use super::{action, inventory};

pub(super) use traffic_rewrite_model::rewrite::inventory::is_skipped;

pub(super) fn has_skips(state: &RewriteState) -> bool {
    state
        .api_inventory
        .iter()
        .any(|item| item.status == RewriteApiStatus::Skipped)
}

pub(super) fn apply(target_root: &Path, state: &mut RewriteState) -> Result<bool> {
    // A running deterministic traffic operation finishes before inputs change.
    if super::execution::owned_by_other_process(target_root)?
        || !matches!(
            super::traffic_operation::state(target_root)?,
            super::traffic_operation::TrafficOperationState::Absent
        )
    {
        return Ok(false);
    }
    if state.phase == RewritePhase::RecordingRequired {
        return Ok(false);
    }
    inventory::revalidation_round::reconcile_skips(state);
    let cleared_selection = is_skipped(state, &state.api);
    if cleared_selection {
        state
            .parked_slices
            .insert(state.api.clone(), state.active_slice.clone());
        state.current_api_index = None;
        state.active_slice = RewriteSliceState::pending(String::new(), String::new());
        state.phase = RewritePhase::SliceComplete;
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
            state.bump();
            return Ok(true);
        }
    }
    if cleared_selection {
        state.bump();
    }
    Ok(cleared_selection)
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
                summary: format!("{api} is skipped; no verification was performed for this scope"),
                e2e_current: false,
            },
        );
        envelope.latest_focused_e2e = None;
        envelope
    })
}
