//! Changes to Comparison requirements reuse current Replay evidence and only
//! reopen the missing validation stage. Recording batches do not own this policy.
use std::path::Path;

use anyhow::Result;

use crate::rewrite::model::{
    RewriteApiStatus, RewriteIssueKind, RewritePhase, RewriteSliceState, RewriteState,
};
use crate::rewrite::{fingerprint, inventory};

pub(super) fn bind_selected(
    state: &mut RewriteState,
    policy: &crate::config::regression::RegressionScope,
) -> bool {
    if state.phase != RewritePhase::ComparisonRecordingRequired {
        return false;
    }
    let Some(run_id) = &policy.comparison_run_id else {
        return false;
    };
    if state.comparison_run_id.as_ref() == Some(run_id) {
        return false;
    }
    state.comparison_run_id = Some(run_id.clone());
    state.comparison_rejection = None;
    true
}

pub(super) fn reconcile(state: &mut RewriteState) -> Result<bool> {
    let mut changed = false;
    let required = state.require_comparison;
    for index in 0..state.api_inventory.len() {
        let item = &state.api_inventory[index];
        if item.status == RewriteApiStatus::Skipped {
            continue;
        }
        if required && item.status == RewriteApiStatus::Complete && !item.comparison_current {
            let mut slice = state
                .parked_slices
                .remove(&item.api)
                .unwrap_or(inventory::completed_slice(item)?);
            slice.phase = RewritePhase::ApiPending;
            state.parked_slices.insert(item.api.clone(), slice);
            state.api_inventory[index].status = RewriteApiStatus::Pending;
            changed = true;
        }
    }
    if state.current_api_index.is_some() {
        changed |= reconcile_slice(&mut state.active_slice, required);
    }
    for (api, slice) in &mut state.parked_slices {
        if state
            .api_inventory
            .iter()
            .any(|item| item.api == *api && item.status != RewriteApiStatus::Skipped)
            && reconcile_slice(slice, required)
        {
            if let Some(item) = state.api_inventory.iter_mut().find(|item| item.api == *api) {
                item.status = RewriteApiStatus::Pending;
            }
            changed = true;
        }
    }
    Ok(changed)
}

fn reconcile_slice(slice: &mut RewriteSliceState, required: bool) -> bool {
    if required && slice.phase == RewritePhase::SliceComplete && !slice.comparison_current {
        slice.phase = RewritePhase::ApiPending;
        return true;
    }
    if !required
        && (slice.phase == RewritePhase::ComparisonRecordingRequired
            || slice
                .active_issue
                .as_ref()
                .is_some_and(|issue| issue.kind == RewriteIssueKind::Comparison))
    {
        slice.phase = RewritePhase::SliceComplete;
        slice.active_issue = None;
        slice.route = None;
        slice.system_repair_accepted = false;
        slice.rule_replay_pending = false;
        slice.rule_plan = None;
        slice.dependency_rule_plan = None;
        slice.recorder_capture_plan = None;
        return true;
    }
    false
}

pub(in crate::rewrite) fn start_if_required(root: &Path, state: &mut RewriteState) -> Result<bool> {
    if !state.require_comparison
        || !state.e2e_current
        || state.comparison_current
        || state.target_fingerprint.as_deref()
            != Some(fingerprint::repository_fingerprint(root)?.as_str())
    {
        return Ok(false);
    }
    state.phase = RewritePhase::ComparisonRecordingRequired;
    state.comparison_run_id = None;
    state.comparison_rejection = None;
    state.bump();
    Ok(true)
}
