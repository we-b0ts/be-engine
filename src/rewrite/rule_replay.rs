//! API-scoped verification admission after successful rule application.
//! A pending request retains the dirty issue until a new Replay is finalized;
//! ordinary source review, target quality and traffic leases remain mandatory.
use super::RewriteWorkScope;
use super::model::{RewritePhase, RewriteSliceState, RewriteState};

pub(super) fn request(state: &mut RewriteState) {
    state.rule_replay_pending = true;
    state.e2e_current = false;
    state.comparison_current = false;
}

pub(super) fn pending(slice: &RewriteSliceState) -> bool {
    slice.rule_replay_pending
        && slice.phase == RewritePhase::ImplementationRequired
        && slice.active_issue.is_some()
}

pub(super) fn ready(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    let RewriteWorkScope::Api { api } = scope else {
        return false;
    };
    if super::regression_scope::is_skipped(state, api) {
        return false;
    }
    if api == &state.api {
        pending(&state.active_slice)
    } else {
        state.parked_slices.get(api).is_some_and(pending)
    }
}

pub(super) fn any_ready(state: &RewriteState) -> bool {
    std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .any(|slice| {
            ready(
                state,
                &RewriteWorkScope::Api {
                    api: slice.api.clone(),
                },
            )
        })
}

#[cfg(test)]
mod tests;
