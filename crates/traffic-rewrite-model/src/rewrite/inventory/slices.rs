//! Immutable API slice selection and initial slice construction.
use crate::rewrite::model::{
    RewriteApiProgress, RewriteApiStatus, RewritePhase, RewriteSliceState, RewriteState,
};
use anyhow::{Context, Result};
use traffic_engine::RecordingApi;

pub fn scoped(state: &RewriteState, requested_api: Option<&RecordingApi>) -> Result<RewriteState> {
    let Some(requested_api) = requested_api else {
        return Ok(state.clone());
    };
    let requested = requested_api.to_string();
    if state.api == requested {
        return Ok(state.clone());
    }
    let index = state
        .api_inventory
        .iter()
        .position(|item| item.api == requested)
        .with_context(|| format!("recorded API inventory does not contain {requested:?}"))?;
    let item = &state.api_inventory[index];
    let slice = match state.parked_slices.get(&requested).cloned() {
        Some(slice) => slice,
        None if matches!(
            item.status,
            RewriteApiStatus::Pending | RewriteApiStatus::RevalidationPending
        ) =>
        {
            pending_slice(item)?
        }
        None if item.status == RewriteApiStatus::Complete => completed_slice(item)?,
        None => anyhow::bail!("API {requested} has no concurrent AI work state"),
    };
    let mut scoped = state.clone();
    if matches!(
        state.phase,
        RewritePhase::ImplementationRequired | RewritePhase::SystemRepairRequired
    ) {
        scoped
            .parked_slices
            .insert(state.api.clone(), state.active_slice.clone());
    }
    scoped.parked_slices.remove(&requested);
    scoped.active_slice = slice;
    scoped.current_api_index = Some(index);
    Ok(scoped)
}

pub fn pending_slice(current: &RewriteApiProgress) -> Result<RewriteSliceState> {
    let api = current.api.parse::<RecordingApi>()?;
    Ok(RewriteSliceState::pending(
        current.api.clone(),
        current.source_route.clone().unwrap_or_else(|| {
            if api.is_dynamic() {
                String::new()
            } else {
                api.path_pattern().to_string()
            }
        }),
    ))
}

pub fn completed_slice(current: &RewriteApiProgress) -> Result<RewriteSliceState> {
    let mut slice = pending_slice(current)?;
    slice.phase = RewritePhase::SliceComplete;
    slice.target_fingerprint = current.verified_target_fingerprint.clone();
    slice.e2e_current = current.e2e_current;
    Ok(slice)
}

pub fn with_slice_mut<T>(
    state: &mut RewriteState,
    api: &str,
    operation: impl FnOnce(&mut RewriteState) -> Result<T>,
) -> Result<T> {
    if state.api == api {
        return operation(state);
    }
    let slice = state
        .parked_slices
        .remove(api)
        .with_context(|| format!("API {api} has no concurrent AI work state"))?;
    let active = std::mem::replace(&mut state.active_slice, slice);
    let current_index = state.current_api_index;
    state.current_api_index = state.api_inventory.iter().position(|item| item.api == api);
    let result = operation(state);
    let updated = std::mem::replace(&mut state.active_slice, active);
    state.current_api_index = current_index;
    state.parked_slices.insert(api.to_string(), updated);
    result
}

pub fn is_skipped(state: &RewriteState, api: &str) -> bool {
    state
        .api_inventory
        .iter()
        .any(|item| item.api == api && item.status == RewriteApiStatus::Skipped)
}
