//! Resolve runtime handles without requiring coordinator-owned engine IDs.
use anyhow::{Result, ensure};

use super::super::model::RewriteState;
use super::super::work_scope::RewriteWorkScope;
use super::runtime::{self, RewriteWorkerReportOptions};
use traffic_rewrite_agents::implementer::legacy;

pub(super) fn scope_for_handle(state: &RewriteState, handle: &str) -> Result<RewriteWorkScope> {
    ensure!(
        state.implementers.is_none(),
        "pooled workflows do not resolve API ownership from a runtime handle"
    );
    legacy::resolve_handle(state, handle, runtime::scopes(state))
}

fn observation_scopes(state: &RewriteState) -> Vec<RewriteWorkScope> {
    let mut scopes = runtime::scopes(state);
    // A rule can release worker delivery while its existing task is still
    // finishing. Accept runtime observations without redispatching that task.
    scopes.extend(
        std::iter::once(&state.active_slice)
            .chain(state.parked_slices.values())
            .map(|slice| super::super::api_selector::work_scope(state, &slice.api))
            .filter(|scope| {
                super::super::rule_replay::ready(state, scope)
                    || super::super::replay_admission::admitted(state, scope)
                    || super::super::replay_admission::all_ready(state, scope, |slice| {
                        slice.engine_retry_running
                    })
            }),
    );
    scopes
}

pub(super) fn report_scope(
    state: &RewriteState,
    options: &RewriteWorkerReportOptions,
) -> Result<RewriteWorkScope> {
    legacy::report_scope(state, options, runtime::scopes(state), || {
        observation_scopes(state)
    })
}
