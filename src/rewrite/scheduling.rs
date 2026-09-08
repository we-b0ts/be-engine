//! Idle-work selection and resumable external blocking. Traffic ownership stays
//! with the operation lease; worker dispatch remains in worker::scheduler.
use std::path::Path;

use super::model::{RewriteAction, RewriteApiStatus, RewritePhase, RewriteState};
use super::{action, inventory, process_outputs, repair, worker};

pub(super) fn repair_action(target_root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    if !inventory::can_switch_api(state) {
        return None;
    }
    repair_apis(state).into_iter().find_map(|api| {
        let mut scoped = inventory::scoped(state, Some(&api.parse().ok()?)).ok()?;
        scoped.process_outputs.current_id = None;
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
        .then(|| {
            state
                .api_inventory
                .iter()
                .find(|item| item.status == RewriteApiStatus::RevalidationPending)
                .map(|item| item.api.as_str())
        })
        .flatten()
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
        .find(|slice| slice.api != state.api && slice.system_repair_accepted)
        .map(|slice| slice.api.as_str());
    if let Some(api) = accepted.or_else(|| inventory::next_pending_api_for_concurrent_work(state)) {
        return Some(advance(target_root, api, "verify ready API"));
    }
    if let Some(id) = process_outputs::next_eligible_id(state) {
        return Some(RewriteAction::AdvanceRequired {
            summary: format!("verify ready process output {id}"),
            command: action::next_command_for_process_output(target_root, id),
        });
    }
    if let Some(api) = revalidation_api(state) {
        return Some(advance(
            target_root,
            api,
            "use idle verification capacity to revalidate API",
        ));
    }
    let blocked = repair_apis(state);
    let only_complete_or_repair = !blocked.is_empty()
        && state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Complete || blocked.contains(&item.api));
    if only_complete_or_repair && worker::runtime::scopes(state).is_empty() {
        // Deferred process captures cannot be validated before their API baseline.
        // Keep them visible as dependencies of the blocked stop, never completed.
        return Some(RewriteAction::Blocked {
            summary: "stop this coordinator run: remaining APIs require external system repair; preserve bindings and evidence, then resume with global status after repair".into(),
            system_repair_apis: blocked,
            dependent_process_outputs: state.process_outputs.inventory.iter()
                .filter(|item| item.status != super::process_output_model::RewriteProcessOutputStatus::Complete)
                .map(|item| item.id.clone()).collect(),
            resume: action::status_command_for_api(target_root, None),
        });
    }
    if !worker::runtime::scopes(state).is_empty() || !blocked.is_empty() {
        return Some(RewriteAction::WaitRequired {
            summary: "wait for worker or engine progress; after waiting inspect task-runtime completion and interruption events, then refresh global status".into(),
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
    RewriteAction::AdvanceRequired {
        summary: format!("{purpose} {api}"),
        command: action::next_command_for_api(target_root, api),
    }
}

#[cfg(test)]
mod tests;
