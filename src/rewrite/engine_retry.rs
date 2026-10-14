//! Durable changed-engine retries, including the last unfinished API route.
use super::model::{
    RewriteApiStatus, RewriteIssueKind, RewritePhase, RewriteSliceState, RewriteState,
};

#[cfg(test)]
fn eligible(slice: &RewriteSliceState, engine: &str) -> bool {
    eligible_failure(slice, engine, false)
}

/// The final route may refresh any failed Replay after a known engine change.
/// Inventory-only checks keep status independent of recording/report I/O.
pub(super) fn pending(state: &RewriteState, slice: &RewriteSliceState) -> bool {
    eligible_failure(
        slice,
        crate::build_info::ENGINE_FINGERPRINT,
        last_unfinished_route(state, &slice.api),
    )
}

fn last_unfinished_route(state: &RewriteState, api: &str) -> bool {
    if super::regression_scope::is_skipped(state, api) {
        return false;
    }
    let route = super::api_selector::public_api(api);
    let mut found = false;
    for item in &state.api_inventory {
        if matches!(
            item.status,
            RewriteApiStatus::Complete
                | RewriteApiStatus::RevalidationPending
                | RewriteApiStatus::Skipped
        ) {
            continue;
        }
        if super::api_selector::public_api(&item.api) != route {
            return false;
        }
        found = true;
    }
    found
}

fn eligible_failure(slice: &RewriteSliceState, engine: &str, final_route: bool) -> bool {
    slice.phase == RewritePhase::ImplementationRequired
        && !slice.engine_retry_running
        && slice.active_issue.as_ref().is_some_and(|issue| {
            slice.attempts.last().is_some_and(|attempt| {
                !attempt.passed
                    && attempt.attempt == issue.attempt
                    && attempt.engine_fingerprint.as_deref() != Some(engine)
                    && (issue.kind == RewriteIssueKind::TargetRuntime
                        || issue.kind == RewriteIssueKind::Dependency
                            && super::replay_admission::dependency_only(attempt)
                        || final_route
                            && issue.kind != RewriteIssueKind::TargetQuality
                            && attempt.engine_fingerprint.is_some()
                            && attempt.counts.selected > 0)
            })
        })
        && !slice.engine_retry_fingerprints.contains(engine)
        && slice.rule_plan.is_none()
        && slice.dependency_rule_plan.is_none()
        && slice.recorder_capture_plan.is_none()
        && slice.route.is_none()
}

pub(super) fn any_pending(state: &RewriteState) -> bool {
    std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .any(|slice| {
            pending(state, slice) && !super::regression_scope::is_skipped(state, &slice.api)
        })
}

/// Called under coordinator lock after review/resource admission and before Replay.
/// Saving the mutated state precedes starting a new Replay attempt.
fn consume(slice: &mut RewriteSliceState, final_route: bool) -> bool {
    if !eligible_failure(slice, crate::build_info::ENGINE_FINGERPRINT, final_route) {
        return false;
    }
    slice.engine_retry_running = true;
    slice
        .engine_retry_fingerprints
        .insert(crate::build_info::ENGINE_FINGERPRINT.into())
}

pub(super) fn reserve(
    state: &mut RewriteState,
    prepared: Option<&mut super::api_batch::PreparedRoute>,
) -> bool {
    let Some(prepared) = prepared else {
        let final_route = last_unfinished_route(state, &state.api);
        return consume(&mut state.active_slice, final_route);
    };
    let mut changed = false;
    for (api, slice) in &mut prepared.slices {
        if consume(slice, last_unfinished_route(state, api)) {
            let persisted = if state.api == *api {
                &mut state.active_slice
            } else {
                state
                    .parked_slices
                    .get_mut(api)
                    .expect("retry has a retained slice")
            };
            persisted.engine_retry_fingerprints = slice.engine_retry_fingerprints.clone();
            persisted.engine_retry_running = true;
            changed = true;
        }
    }
    changed
}

/// Recovery/error cleanup never refunds a consumed engine revision.
pub(super) fn clear_running(state: &mut RewriteState) -> bool {
    let mut changed = false;
    for slice in std::iter::once(&mut state.active_slice).chain(state.parked_slices.values_mut()) {
        changed |= std::mem::take(&mut slice.engine_retry_running);
    }
    changed
}

#[cfg(test)]
mod tests;
