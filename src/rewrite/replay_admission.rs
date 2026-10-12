//! Verification permits independent of an external worker handoff.
use super::{
    RewriteWorkScope,
    model::{RewritePhase, RewriteSliceState, RewriteState},
};

pub(super) fn slice_ready(slice: &RewriteSliceState) -> bool {
    super::rule_replay::pending(slice)
        || super::engine_retry::pending(slice)
        || slice.system_repair_accepted
}

pub(super) fn admitted(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    all_ready(state, scope, slice_ready)
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
