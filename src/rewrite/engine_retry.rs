//! One fresh runtime verification per changed engine build, including legacy failures.
use super::model::{RewriteIssueKind, RewritePhase, RewriteSliceState, RewriteState};

pub(super) fn pending(slice: &RewriteSliceState) -> bool {
    eligible(slice, crate::build_info::ENGINE_FINGERPRINT)
}

fn eligible(slice: &RewriteSliceState, engine: &str) -> bool {
    slice.phase == RewritePhase::ImplementationRequired
        && !slice.engine_retry_running
        && slice.active_issue.as_ref().is_some_and(|issue| {
            issue.kind == RewriteIssueKind::TargetRuntime
                && slice.attempts.last().is_some_and(|attempt| {
                    !attempt.passed
                        && attempt.attempt == issue.attempt
                        && attempt.engine_fingerprint.as_deref() != Some(engine)
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
        .any(|slice| pending(slice) && !super::regression_scope::is_skipped(state, &slice.api))
}

/// Called under coordinator lock after review/resource admission and before Replay.
/// Saving the mutated state precedes starting a new Replay attempt.
pub(super) fn consume(slice: &mut RewriteSliceState) -> bool {
    if !pending(slice) {
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
        return consume(&mut state.active_slice);
    };
    let mut changed = false;
    for (api, slice) in &mut prepared.slices {
        if consume(slice) {
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
