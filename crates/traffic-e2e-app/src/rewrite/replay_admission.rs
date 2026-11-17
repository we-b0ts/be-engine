//! Verification permits independent of an external worker handoff.
use super::{
    RewriteWorkScope,
    model::{RewritePhase, RewriteSliceState, RewriteState},
};

pub(super) fn pending_transaction(slice: &RewriteSliceState) -> bool {
    slice
        .rule_plan
        .as_ref()
        .is_some_and(|plan| plan.unified.is_some())
}

pub(super) fn applying_policy(state: &RewriteState) -> bool {
    std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .any(|slice| {
            slice
                .rule_plan
                .as_ref()
                .and_then(|plan| plan.unified.as_ref())
                .is_some_and(|record| record.applying())
        })
}

pub(super) fn slice_ready(state: &RewriteState, slice: &RewriteSliceState) -> bool {
    !applying_policy(state)
        && !pending_transaction(slice)
        && (super::rule_replay::pending(slice)
            || super::engine_retry::pending(state, slice)
            || slice.system_repair_accepted)
}

pub(super) fn admitted(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    all_ready(state, scope, |slice| slice_ready(state, slice))
}

pub(super) fn all_ready(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    mut admitted: impl FnMut(&RewriteSliceState) -> bool,
) -> bool {
    if applying_policy(state) {
        return false;
    }
    let RewriteWorkScope::Api { api } = scope;
    let mut dirty = std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .filter(|slice| {
            (if api.contains(' ') {
                slice.api == *api
            } else {
                super::api_selector::public_api(&slice.api) == api
            }) && !super::regression_scope::is_skipped(state, &slice.api)
                && slice.phase == RewritePhase::ImplementationRequired
        })
        .peekable();
    dirty.peek().is_some() && dirty.all(|slice| !pending_transaction(slice) && admitted(slice))
}

pub(super) fn dependency_only(attempt: &super::model::RewriteAttemptSummary) -> bool {
    attempt.gates.responses == crate::E2eResponseGate::Passed
        && attempt.gates.replay == crate::E2eReplayGate::Complete
        && attempt.gates.dependencies == crate::E2eDependencyGate::Dirty
        && attempt.counts.selected > 0
        && attempt.counts.executed == attempt.counts.selected
        && attempt.counts.response_passed == attempt.counts.executed
        && attempt.counts.response_nonpassing == 0
        && attempt.counts.response_incomplete == 0
}
