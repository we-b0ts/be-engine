//! Adoption of an explicitly selected, finalized standard recording.
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::config::{PATH, RegressionScope};
use crate::rewrite::{
    artifacts, inventory,
    model::{RewritePhase, RewriteSliceState, RewriteState},
};

struct Selection {
    run_id: String,
    scope: Vec<String>,
}

fn load(target_root: &Path, policy: &RegressionScope) -> Result<Option<Selection>> {
    let Some(run_id) = &policy.recording_run_id else {
        return Ok(None);
    };
    let validate = || -> Result<Selection> {
        let scope = artifacts::standard_recording_scope(target_root, run_id)?;
        let apis =
            artifacts::standard_recording_apis_for_scope(target_root, run_id, scope.clone())?;
        for api in policy.selectors() {
            ensure!(
                apis.contains(api),
                "API {api:?} is absent from the selected recording inventory"
            );
        }
        Ok(Selection {
            run_id: run_id.clone(),
            scope,
        })
    };
    validate().with_context(|| format!(
        "{PATH}: recording_run_id {run_id:?} cannot be reused; select an existing completed standard recording with usable cases"
    )).map(Some)
}

pub(in crate::rewrite) fn validate_uninitialized(target_root: &Path) -> Result<()> {
    load(target_root, &RegressionScope::load(target_root)?)?;
    Ok(())
}

pub(super) fn apply(
    target_root: &Path,
    state: &mut RewriteState,
    policy: &RegressionScope,
) -> Result<bool> {
    if state.regression.as_ref().is_some_and(|origin| {
        origin.superseded_recording_run_id.is_some()
            && origin.superseded_recording_run_id == policy.recording_run_id
    }) {
        // Explicit new-traffic purpose supersedes the old local recording pin.
        return Ok(false);
    }
    let Some(selection) = load(target_root, policy)? else {
        return Ok(false);
    };
    if state.recording_run_id == selection.run_id {
        return Ok(false);
    }
    ensure!(
        state.recording_refresh.is_none(),
        "{PATH}: remove recording_run_id before completing the pending recorder-capture refresh"
    );
    inventory::reset_for_recording(state);
    state.recording_apis = selection.scope;
    state.recording_run_id = selection.run_id;
    state.recording_rejection = None;
    state.recording_request_reason = None;
    state.recording_input_case_source = None;
    state.recording_input_diagnosis = None;
    state.case_pattern_identification = None;
    state.active_slice = RewriteSliceState::pending(String::new(), String::new());
    state.phase = RewritePhase::RecordingRequired;
    Ok(true)
}

pub(in crate::rewrite) fn ensure_fresh_allowed(target_root: &Path) -> Result<()> {
    ensure!(
        RegressionScope::load(target_root)?
            .recording_run_id
            .is_none(),
        "{PATH}: recording_run_id selects existing evidence; remove it before requesting a fresh standard recording"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
