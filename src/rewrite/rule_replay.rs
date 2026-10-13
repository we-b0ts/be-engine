//! API-scoped verification admission after successful rule application.
//! A pending request retains the dirty issue until a new Replay is finalized;
//! ordinary source review, target quality and traffic leases remain mandatory.
use super::RewriteWorkScope;
use super::model::{RewritePhase, RewriteSliceState, RewriteState};

pub(super) fn request(state: &mut RewriteState) {
    state.rule_replay_pending = true;
    state.e2e_current = false;
}

/// A changed process rule first reclassifies existing evidence. If only
/// dependencies remain dirty, request one real Replay for affected route methods.
/// Unchanged/idempotent application cannot renew a consumed request.
pub(super) fn after_process_rule(state: &mut RewriteState, api: &str, changed: bool) {
    if !changed {
        return;
    }
    let route = super::api_selector::public_api(api);
    for slice in std::iter::once(&mut state.active_slice).chain(state.parked_slices.values_mut()) {
        if super::api_selector::public_api(&slice.api) == route
            && slice.phase == RewritePhase::ImplementationRequired
            && slice.active_issue.as_ref().is_some_and(|issue| {
                issue.kind == super::model::RewriteIssueKind::Dependency
                    && slice.attempts.last().is_some_and(|attempt| {
                        !attempt.passed
                            && attempt.attempt == issue.attempt
                            && super::replay_admission::dependency_only(attempt)
                    })
            })
        {
            slice.rule_replay_pending = true;
            slice.e2e_current = false;
        }
    }
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
