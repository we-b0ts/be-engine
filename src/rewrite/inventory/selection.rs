//! API activation preserves implementation and external-repair slices.
use super::*;

pub(in crate::rewrite) fn can_switch_api(state: &RewriteState) -> bool {
    matches!(
        state.phase,
        RewritePhase::ApiPending
            | RewritePhase::ImplementationRequired
            | RewritePhase::SystemRepairRequired
            | RewritePhase::SliceComplete
    ) && state.case_pattern_identification.is_none()
        && !crate::rewrite::transition::replay_completion_pending(state)
}

pub(in crate::rewrite) fn activate_requested(
    state: &mut RewriteState,
    requested_api: Option<&RecordingApi>,
) -> Result<bool> {
    let Some(requested_api) = requested_api else {
        return Ok(false);
    };
    let requested = requested_api.to_string();
    if state.api == requested {
        return Ok(false);
    }
    ensure!(
        can_switch_api(state),
        "API {} is currently in {:?}; wait for its deterministic traffic operation before selecting {requested}",
        state.api,
        state.phase
    );
    let requested_index = state
        .api_inventory
        .iter()
        .position(|item| item.api == requested)
        .with_context(|| format!("recorded API inventory does not contain {requested:?}"))?;
    ensure!(
        matches!(
            state.api_inventory[requested_index].status,
            RewriteApiStatus::Pending
                | RewriteApiStatus::ImplementationRequired
                | RewriteApiStatus::SystemRepairRequired
                | RewriteApiStatus::RevalidationPending
        ),
        "API {requested} is not available for concurrent AI work"
    );
    if matches!(
        state.phase,
        RewritePhase::ImplementationRequired | RewritePhase::SystemRepairRequired
    ) {
        park_current_issue(state)?;
    } else if state.phase == RewritePhase::ApiPending {
        let current_index = state
            .current_api_index
            .context("active API has no inventory index")?;
        state.api_inventory[current_index].status = RewriteApiStatus::Pending;
    }
    state.current_api_index = Some(requested_index);
    state.api_inventory[requested_index].status = RewriteApiStatus::Active;
    state.active_slice = match state.parked_slices.remove(&requested) {
        Some(slice) => slice,
        None => pending_slice(&state.api_inventory[requested_index])?,
    };
    state.bump();
    Ok(true)
}

fn park_current_issue(state: &mut RewriteState) -> Result<()> {
    ensure!(
        matches!(
            state.phase,
            RewritePhase::ImplementationRequired | RewritePhase::SystemRepairRequired
        ),
        "only an implementation or system repair issue can be parked"
    );
    let index = state
        .current_api_index
        .context("active API has no inventory index")?;
    let attempts = state.attempts.len();
    let e2e_current = state.e2e_current;
    let current = state
        .api_inventory
        .get_mut(index)
        .context("active API inventory index is invalid")?;
    current.status = if state.active_slice.phase == RewritePhase::SystemRepairRequired {
        RewriteApiStatus::SystemRepairRequired
    } else {
        RewriteApiStatus::ImplementationRequired
    };
    current.attempts = attempts;
    current.e2e_current = e2e_current;
    state
        .parked_slices
        .insert(state.api.clone(), state.active_slice.clone());
    Ok(())
}
