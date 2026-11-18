use std::path::Path;

use super::super::model::{RewriteAction, RewriteState};
use super::super::work_scope::RewriteWorkScope;
use super::super::{action, inventory};
use super::model::{
    RewriteWorkerCoverageState as Coverage, RewriteWorkerInventoryCommands,
    RewriteWorkerInventoryItem,
};
use super::runtime;

pub(crate) fn inventory(
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
                runtime::report_command_for_scope(target_root, state, &scope, false);
            RewriteWorkerInventoryItem {
                delivery_commit: state
                    .worker_bindings
                    .get(&scope.binding_key())
                    .and_then(|b| b.review_report.as_ref())
                    .map(|r| r.head_revision.clone()),
                worker_worktree: state
                    .worker_bindings
                    .get(&scope.binding_key())
                    .and_then(|b| b.review_assignment.as_ref())
                    .map(|a| a.worktree.clone()),
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
/// Runtime dispatch and status checks stay immediate. Between group rounds,
/// ready handoffs wait for eligible first attempts so implementation can fan out.
pub(crate) fn global_action(
    target_root: &Path,
    state: &RewriteState,
    busy: bool,
) -> Option<RewriteAction> {
    if state.case_pattern_identification.is_some() || state.revalidation_round.is_some() {
        return None;
    }
    let first_pass_ready = super::super::scheduling::first_pass_api(state).is_some();
    let integration_busy = busy || state.group_replay.is_some();
    let scope = runtime::scopes(state)
        .into_iter()
        .filter_map(|scope| {
            let priority = match runtime::coverage(state, &scope) {
                Coverage::DispatchRequired | Coverage::ResumeRequired
                    if state.implementers.is_none() =>
                {
                    0
                }
                Coverage::StatusRequired => 1,
                Coverage::IntegrationRequired if !integration_busy && !first_pass_ready => 2,
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

pub(crate) fn scope_action(
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
            execution_mode: None,
            summary: format!(
                "must actually invoke built-in ListAgents (/list-agents) in Claude Code or equivalent runtime status tools for all workers awaiting results, including {}; collect results before reporting changes or required refreshes through the owning commands.report_worker. Resolve omitted or unclassified tasks through results or individual queries; historical dispatch confirmation is not runtime status",
                scope.label()
            ),
            report_worker: runtime::report_command_for_scope(target_root, state, scope, false),
            worker,
        },
        Coverage::IntegrationRequired => RewriteAction::IntegrationRequired {
            summary: format!(
                "ready handoffs await integration; the current entry is {}. Select ready deliveries and their exact delivery_commit from inventory. The integrator merges them and resolves conflicts, then returns the candidate commit without review check or repository quality gates. The coordinator publishes that exact commit and reports integrated with --delivery-commit and each original handoff ID. Preserve already integrated handoffs. A confirmed integration defect can be returned through commands.report_rework. Source review, line limits and isolation checks run once on the final candidate before full revalidation",
                scope.label()
            ),
            handoff_id: runtime::observation(state, scope)
                .and_then(|value| value.handoff_id.clone())
                .expect("ready handoff has an identity"),
            report_worker: runtime::report_command_for_scope(target_root, state, scope, true),
            report_rework: runtime::rework_command_for_scope(target_root, state, scope),
            worker,
        },
        Coverage::VerificationRequired => action::replay_advance(
            target_root,
            &scope.binding_key(),
            format!(
                "worker handoff for {} is integrated; execute coordinator acceptance",
                scope.label()
            ),
        ),
        _ if state.implementers.is_some() => super::super::implementer::action(target_root, state)
            .ok().flatten().unwrap_or_else(|| RewriteAction::WaitRequired {
                execution_mode: None,
                summary: "wait for the current group Replay or repository analysis before dispatching this API through its implementer pool".into(),
                resource: "implementer_dispatch".into(), requested_api: Some(scope.binding_key()), blocking_api: None,
                active_operation: None, retry_after_seconds: 30,
                status: action::status_command_for_api(target_root, None),
            }),
        _ => super::implementation_action(target_root, &scoped, None),
    }
}

pub(crate) fn after_dispatch(target_root: &Path, state: &RewriteState) -> RewriteAction {
    let scope = super::active_scope(state).expect("implementation phase has a work scope");
    if let Some(action) = global_action(target_root, state, false) {
        return action;
    }
    if let Some(action) = super::super::scheduling::idle_action(target_root, state) {
        return action;
    }
    scope_action(target_root, state, &scope)
}

pub(crate) fn acceptance_gate(
    target_root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Option<RewriteAction> {
    // Rule/system repair permissions belong to an exact method slice. A worker
    // binding may be route-wide, but it must not erase that precise admission.
    if super::super::replay_admission::admitted(state, scope) {
        return None;
    }
    let scope = super::super::api_selector::canonical_scope(state, scope);
    (super::issue_for_scope(state, &scope).is_some() && !runtime::acceptance_ready(state, &scope))
        .then(|| scope_action(target_root, state, &scope))
}

#[cfg(test)]
mod tests;
