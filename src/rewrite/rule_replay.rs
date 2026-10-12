//! API-scoped verification admission after successful rule application.
//! A pending request retains the dirty issue until a new Replay is finalized;
//! ordinary source review, target quality and traffic leases remain mandatory.
use super::RewriteWorkScope;
use super::model::{RewritePhase, RewriteSliceState, RewriteState};

pub(super) fn request(state: &mut RewriteState) {
    state.rule_replay_pending = true;
    state.e2e_current = false;
}

pub(super) fn pending(slice: &RewriteSliceState) -> bool {
    slice.rule_replay_pending
        && slice.phase == RewritePhase::ImplementationRequired
        && slice.active_issue.is_some()
}

pub(super) fn ready(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    super::replay_admission::all_ready(state, scope, pending)
}

pub(super) fn any_ready(state: &RewriteState) -> bool {
    std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .any(|slice| {
            ready(
                state,
                &RewriteWorkScope::Api {
                    api: super::api_selector::public_api(&slice.api).into(),
                },
            )
        })
}

#[cfg(test)]
mod tests;
