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
                apis.iter()
                    .any(|item| crate::recording_api::identity(item) == api),
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
    let pending_patterns = state
        .case_pattern_identification
        .as_ref()
        .filter(|pending| {
            state.phase == RewritePhase::RecordingRequired
                && pending.recording_run_id == state.recording_run_id
        });
    if policy
        .recording_run_id
        .as_deref()
        .is_some_and(|run_id| run_id == state.recording_run_id)
        && (!state.api_inventory.is_empty() || pending_patterns.is_some())
    {
        // Cases are immutable once adopted. Keep checking the selected run's
        // finalized manifest and newly edited selectors, without rediscovering
        // all cases on every read-only status call.
        artifacts::standard_recording_scope(target_root, &state.recording_run_id).with_context(
            || {
                format!(
                    "{PATH}: recording_run_id {:?} is unavailable",
                    state.recording_run_id
                )
            },
        )?;
        let apis = if state.api_inventory.is_empty() {
            crate::rewrite::case_patterns::canonical_observed_apis(
                target_root,
                &pending_patterns
                    .expect("adopted observation snapshot")
                    .observed_apis,
            )?
        } else {
            state
                .api_inventory
                .iter()
                .map(|item| item.api.clone())
                .collect()
        };
        for api in policy.selectors() {
            let present = apis
                .iter()
                .any(|item| crate::recording_api::identity(item) == api);
            if !present && state.api_inventory.is_empty() {
                // Older recordings can carry api_pattern values absent from
                // today's policy and the raw observation snapshot. Preserve
                // their selector semantics through the validated discovery path.
                load(target_root, policy)?;
                return Ok(false);
            }
            ensure!(
                present,
                "{PATH}: API {api:?} is absent from the selected recording inventory"
            );
        }
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
    state.recording_after_run_id = None;
    state.recording_rejection = None;
    state.recording_request_reason = None;
    state.recording_input_case_source = None;
    state.recording_input_diagnosis = None;
    state.case_pattern_identification = None;
    state.active_slice = RewriteSliceState::pending(String::new(), String::new());
    state.phase = RewritePhase::RecordingRequired;
    Ok(true)
}

pub(in crate::rewrite) fn has_active_pin(target_root: &Path, state: &RewriteState) -> Result<bool> {
    let policy = RegressionScope::load(target_root)?;
    Ok(policy.recording_run_id.is_some()
        && !state.regression.as_ref().is_some_and(|origin| {
            origin.superseded_recording_run_id.is_some()
                && origin.superseded_recording_run_id == policy.recording_run_id
        }))
}

pub(in crate::rewrite) fn ensure_fresh_allowed(
    target_root: &Path,
    state: &RewriteState,
) -> Result<()> {
    ensure!(
        !has_active_pin(target_root, state)?,
        "{PATH}: recording_run_id selects existing evidence; remove it before requesting a fresh standard recording"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
