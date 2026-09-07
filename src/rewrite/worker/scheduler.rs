use std::path::Path;

use super::super::model::{RewriteAction, RewritePhase, RewriteState};
use super::super::process_output_model::RewriteWorkScope;
use super::super::{action, evidence, inventory, process_outputs};
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
                RewriteWorkScope::ProcessOutput { id } => action::command(
                    target_root,
                    vec!["status".into(), "--process-output".into(), id.clone()],
                    Vec::new(),
                ),
            };
            let report_worker = runtime::report_command(target_root, &worker.dispatch_id, false);
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
/// Delivery and runtime checks precede integration; neither mutates active selection.
pub(in crate::rewrite) fn global_action(
    target_root: &Path,
    state: &RewriteState,
    busy: bool,
) -> Option<RewriteAction> {
    if state.case_pattern_identification.is_some() {
        return None;
    }
    let scope = runtime::scopes(state)
        .into_iter()
        .filter_map(|scope| {
            let priority = match runtime::coverage(state, &scope) {
                Coverage::DispatchRequired | Coverage::ResumeRequired => 0,
                Coverage::StatusRequired => 1,
                Coverage::IntegrationRequired if !busy => 2,
                Coverage::VerificationRequired
                    if !busy
                        && (matches!(scope, RewriteWorkScope::ProcessOutput { .. })
                            || matches!(
                                state.phase,
                                RewritePhase::ApiPending | RewritePhase::ImplementationRequired
                            )) =>
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
    let issue = super::issue_for_scope(&scoped, scope).expect("unresolved scope has an issue");
    let evidence = evidence::overview_command(target_root, &scoped, scope, issue);
    match runtime::coverage(state, scope) {
        Coverage::StatusRequired => RewriteAction::WorkerStatusRequired {
            summary: format!(
                "inspect the actual bound task for {}; report running, idle, or handoff_ready through commands.report_worker; historical dispatch confirmation is not runtime status",
                scope.label()
            ),
            report_worker: runtime::report_command(target_root, &worker.dispatch_id, false),
            worker,
            evidence,
        },
        Coverage::IntegrationRequired => RewriteAction::IntegrationRequired {
            summary: format!(
                "integrate the ready worker handoff for {}, including its coordinator inputs, then report integrated",
                scope.label()
            ),
            handoff_id: runtime::observation(state, scope)
                .and_then(|value| value.handoff_id.clone())
                .expect("ready handoff has an identity"),
            report_worker: runtime::report_command(target_root, &worker.dispatch_id, true),
            worker,
            evidence,
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
    if let Some(api) = inventory::next_pending_api_for_concurrent_work(state) {
        return RewriteAction::AdvanceRequired {
            summary: format!("execute commands.advance to continue with pending API {api}"),
            command: action::next_command_for_api(target_root, api),
        };
    }
    if let Some(id) = process_outputs::next_eligible_id(state) {
        return RewriteAction::AdvanceRequired {
            summary: format!("execute commands.advance to verify process output {id}"),
            command: action::next_command_for_process_output(target_root, id),
        };
    }
    if runtime::coverage(state, &scope) == Coverage::Running {
        return RewriteAction::WaitRequired {
            summary: "all remaining items are waiting; collect worker completion events or retry global status after 30 seconds".into(),
            resource: "worker_handoff".into(),
            requested_api: None,
            blocking_api: None,
            active_operation: None,
            retry_after_seconds: 30,
            status: action::status_command_for_api(target_root, None),
        };
    }
    scope_action(target_root, state, &scope)
}

pub(in crate::rewrite) fn acceptance_command(
    target_root: &Path,
    scope: &RewriteWorkScope,
) -> super::super::model::RewriteCommandSpec {
    match scope {
        RewriteWorkScope::Api { api } => action::next_command_for_api(target_root, api),
        RewriteWorkScope::ProcessOutput { id } => {
            action::next_command_for_process_output(target_root, id)
        }
    }
}

pub(in crate::rewrite) fn acceptance_gate(
    target_root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Option<RewriteAction> {
    (super::issue_for_scope(state, scope).is_some() && !runtime::acceptance_ready(state, scope))
        .then(|| scope_action(target_root, state, scope))
}

#[cfg(test)]
mod tests;
