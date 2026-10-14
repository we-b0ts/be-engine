//! Verification permits independent of an external worker handoff.
use super::{
    RewriteWorkScope,
    model::{RewritePhase, RewriteSliceState, RewriteState},
};

pub(super) fn slice_ready(state: &RewriteState, slice: &RewriteSliceState) -> bool {
    super::rule_replay::pending(slice)
        || super::engine_retry::pending(state, slice)
        || slice.system_repair_accepted
}

pub(super) fn admitted(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    all_ready(state, scope, |slice| slice_ready(state, slice))
}

pub(super) fn all_ready(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    admitted: impl FnMut(&RewriteSliceState) -> bool,
) -> bool {
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
    dirty.peek().is_some() && dirty.all(admitted)
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
