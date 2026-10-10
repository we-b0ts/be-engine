use std::path::Path;

use super::super::model::{RewriteAction, RewriteState};
use super::super::work_scope::RewriteWorkScope;
use super::super::{action, inventory};
use super::model::{
    RewriteWorkerCoverageState as Coverage, RewriteWorkerInventoryCommands,
    RewriteWorkerInventoryItem,
};
use super::runtime;

pub(in crate::rewrite) fn inventory(
    target_root: &Path,
    state: &RewriteState,
) -> Vec<RewriteWorkerInventoryItem> {
    runtime::scopes(state)
        .into_iter()
        .map(|scope| {
            let worker = super::dispatch_view(state, scope.clone(), None);
            let observation = runtime::observation(state, &scope);
            let status = match &scope {
                RewriteWorkScope::Api { api } => {
                    action::status_command_for_api(target_root, Some(api))
                }
            };
            let report_worker =
                runtime::report_command(target_root, worker.agent_handle.as_deref(), false);
            RewriteWorkerInventoryItem {
                coverage: runtime::coverage(state, &scope),
                observed_at: observation.map(|value| value.observed_at.clone()),
                handoff_id: observation.and_then(|value| value.handoff_id.clone()),
                worker,
                commands: RewriteWorkerInventoryCommands {
                    status,
                    report_worker,
                },
            }
        })
        .collect()
}

/// Reconcile every unresolved scope, including parked APIs, before idle waiting.
/// Runtime dispatch and status checks stay immediate. Ready handoffs wait until
/// every API has had a first verification attempt so implementation can fan out.
pub(in crate::rewrite) fn global_action(
    target_root: &Path,
    state: &RewriteState,
    busy: bool,
) -> Option<RewriteAction> {
    if state.case_pattern_identification.is_some() {
        return None;
    }
    let first_pass_ready =
        inventory::can_switch_api(state) && inventory::has_unattempted_api(state);
    let scope = runtime::scopes(state)
        .into_iter()
        .filter_map(|scope| {
            let priority = match runtime::coverage(state, &scope) {
                Coverage::DispatchRequired | Coverage::ResumeRequired => 0,
                Coverage::StatusRequired => 1,
                Coverage::IntegrationRequired if !busy && !first_pass_ready => 2,
                Coverage::VerificationRequired
                    if !busy && !first_pass_ready && inventory::can_switch_api(state) =>
                {
                    3
                }
                _ => return None,
            };
            Some((priority, scope))
        })
        .min_by_key(|(priority, _)| *priority)?
        .1;
    Some(scope_action(target_root, state, &scope))
}

pub(in crate::rewrite) fn scope_action(
    target_root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> RewriteAction {
    let scoped = runtime::scoped(state, scope).expect("unresolved scope has a retained slice");
    if matches!(scope, RewriteWorkScope::Api { .. })
        && matches!(
            runtime::coverage(state, scope),
            Coverage::IntegrationRequired | Coverage::VerificationRequired
        )
        && (scoped.rule_plan.is_some()
            || scoped.dependency_rule_plan.is_some()
            || scoped.recorder_capture_plan.is_some())
    {
        return action::for_scoped_status(target_root, &scoped)
            .expect("retained plan has a scoped action")
            .action;
    }
    let worker = super::dispatch_view(state, scope.clone(), None);
    match runtime::coverage(state, scope) {
        Coverage::StatusRequired => RewriteAction::WorkerStatusRequired {
            summary: format!(
                "must actually invoke built-in ListAgents (/list-agents) in Claude Code or equivalent runtime status tools for all workers awaiting results, including {}; collect results before reporting changes or required refreshes through the owning commands.report_worker. Resolve omitted or unclassified tasks through results or individual queries; historical dispatch confirmation is not runtime status",
                scope.label()
            ),
            report_worker: runtime::report_command(
                target_root,
                worker.agent_handle.as_deref(),
                false,
            ),
            worker,
        },
        Coverage::IntegrationRequired => RewriteAction::IntegrationRequired {
            summary: format!(
                "integrate the ready worker handoff for {}, including its coordinator inputs, and review the complete candidate before reporting integrated. Keep prior integrated code as the base. For a single new handoff use its scope and handoff ID; a batch may include current integrated handoffs plus ready handoffs, but report integrated only for those still handoff_ready",
                scope.label()
            ),
            handoff_id: runtime::observation(state, scope)
                .and_then(|value| value.handoff_id.clone())
                .expect("ready handoff has an identity"),
            report_worker: runtime::report_command(
                target_root,
                worker.agent_handle.as_deref(),
                true,
            ),
            worker,
        },
        Coverage::VerificationRequired => RewriteAction::AdvanceRequired {
            summary: format!(
                "worker handoff for {} is integrated; execute coordinator acceptance",
                scope.label()
            ),
            command: acceptance_command(target_root, scope),
        },
        _ => super::implementation_action(target_root, &scoped, None),
    }
}

pub(in crate::rewrite) fn after_dispatch(
    target_root: &Path,
    state: &RewriteState,
) -> RewriteAction {
    let scope = super::active_scope(state).expect("implementation phase has a work scope");
    if let Some(action) = global_action(target_root, state, false) {
        return action;
    }
    if let Some(action) = super::super::scheduling::idle_action(target_root, state) {
        return action;
    }
    scope_action(target_root, state, &scope)
}

pub(in crate::rewrite) fn acceptance_command(
    target_root: &Path,
    scope: &RewriteWorkScope,
) -> super::super::model::RewriteCommandSpec {
    match scope {
        RewriteWorkScope::Api { api } => action::next_command_for_api(target_root, api),
    }
}

pub(in crate::rewrite) fn acceptance_gate(
    target_root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Option<RewriteAction> {
    // Rule/system repair permissions belong to an exact method slice. A worker
    // binding may be route-wide, but it must not erase that precise admission.
    if super::super::rule_replay::admitted(state, scope) {
        return None;
    }
    let scope = super::super::api_selector::canonical_scope(state, scope);
    (super::issue_for_scope(state, &scope).is_some() && !runtime::acceptance_ready(state, &scope))
        .then(|| scope_action(target_root, state, &scope))
}

#[cfg(test)]
mod tests;
