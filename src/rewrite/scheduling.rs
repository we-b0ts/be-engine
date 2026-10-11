//! Round-aware verification selection and resumable external blocking. Traffic ownership stays
//! with the operation lease; worker dispatch remains in worker::scheduler.
use std::path::Path;

use super::model::{RewriteAction, RewriteApiStatus, RewritePhase, RewriteState};
use super::{action, inventory, repair, worker};

pub(super) fn repair_action(target_root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    if !inventory::can_switch_api(state) {
        return None;
    }
    repair_apis(state).into_iter().find_map(|api| {
        let scoped = inventory::scoped(state, Some(&api.parse().ok()?)).ok()?;
        let legacy = scoped
            .route
            .as_ref()
            .is_some_and(|route| route.repair_id.is_none());
        (legacy || repair::pending_command(target_root, &scoped).is_some())
            .then(|| action::state_action(target_root, &scoped))
    })
}

pub(super) fn repair_apis(state: &RewriteState) -> Vec<String> {
    state
        .api_inventory
        .iter()
        .filter(|item| item.status != RewriteApiStatus::Skipped)
        .filter_map(|item| {
            let slice = if item.api == state.api {
                Some(&state.active_slice)
            } else {
                state.parked_slices.get(&item.api)
            };
            slice
                .filter(|slice| slice.phase == RewritePhase::SystemRepairRequired)
                .map(|_| item.api.clone())
        })
        .collect()
}

pub(super) fn revalidation_api(state: &RewriteState) -> Option<&str> {
    inventory::can_switch_api(state)
        .then(|| inventory::revalidation_round::next(state))
        .flatten()
}

pub(super) fn round_action(target_root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    state.revalidation_round.as_ref()?;
    revalidation_api(state).map(|api| {
        advance(
            target_root,
            api,
            "continue complete revalidation round for API",
        )
    })
}

/// Called only after ordinary ready worker/native actions have been considered.
pub(super) fn idle_action(target_root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    if !inventory::can_switch_api(state) {
        return None;
    }
    if let Some(action) = repair_action(target_root, state) {
        return Some(action);
    }
    let accepted = state
        .parked_slices
        .values()
        .find(|slice| {
            slice.api != state.api
                && (slice.system_repair_accepted || super::rule_replay::pending(slice))
                && !super::regression_scope::is_skipped(state, &slice.api)
        })
        .map(|slice| slice.api.as_str());
    if let Some(api) = accepted.or_else(|| inventory::next_pending_api_for_concurrent_work(state)) {
        return Some(advance(target_root, api, "verify ready API"));
    }
    if let Some(api) = revalidation_api(state) {
        return Some(advance(
            target_root,
            api,
            "all implementations are accepted or confirmed gaps; revalidate API",
        ));
    }
    let blocked = repair_apis(state);
    let only_complete_or_repair = !blocked.is_empty()
        && state
            .api_inventory
            .iter()
            .all(|item| item.status.is_done() || blocked.contains(&item.api));
    if only_complete_or_repair && worker::runtime::scopes(state).is_empty() {
        // Deferred process captures cannot be validated before their API baseline.
        // Keep them visible as dependencies of the blocked stop, never completed.
        return Some(RewriteAction::Blocked {
            summary: "stop this coordinator run: remaining APIs require external system repair; preserve bindings and evidence, then resume with global status after repair".into(),
            system_repair_apis: blocked.iter()
                .map(|api| super::api_selector::public_api(api).to_string())
                .collect::<std::collections::BTreeSet<_>>().into_iter().collect(),
            resume: action::status_command_for_api(target_root, None),
        });
    }
    if !worker::runtime::scopes(state).is_empty() || !blocked.is_empty() {
        return Some(RewriteAction::WaitRequired {
            execution_mode: None,
            summary: "before waiting on agents and after every wait, must actually invoke built-in ListAgents (/list-agents) in Claude Code or equivalent runtime status tools for all workers awaiting results; reconcile returned states and events, then refresh global status. Historical reports and absent stop events do not establish liveness".into(),
            resource: if worker::runtime::scopes(state).is_empty() { "workflow_dependency" } else { "worker_handoff" }.into(),
            requested_api: None,
            blocking_api: None,
            active_operation: None,
            retry_after_seconds: 30,
            status: action::status_command_for_api(target_root, None),
        });
    }
    None
}

fn advance(target_root: &Path, api: &str, purpose: &str) -> RewriteAction {
    action::replay_advance(
        target_root,
        api,
        format!("{purpose} {}", super::api_selector::public_api(api)),
    )
}

#[cfg(test)]
mod tests;
