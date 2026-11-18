use anyhow::{Context, Result, ensure};
pub(crate) use traffic_rewrite_agents::runtime_identity::{
    validate_identity, validate_runtime_query,
};

#[cfg(test)]
use self::model::RewriteWorkerTransferAuthorization;
use super::action;
use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteCommandSpec, RewritePhase, RewriteState,
    RewriteWorkerDispatchState, RewriteWorkerDispatchView,
};
#[cfg(test)]
use super::model::{RewriteWorkerBinding, RewriteWorkerTransferRecord};
use super::store::RewriteStore;
use super::work_scope::RewriteWorkScope;

#[cfg(test)]
use super::inventory;
#[cfg(test)]
use crate::RecordingApi;

pub(super) mod events;
mod identity;
pub(crate) use traffic_rewrite_agents::implementer::binding::{confirm_binding, dispatch_view};
use traffic_rewrite_agents::implementer::binding::{
    dispatch_id, is_confirmed, issue_for_scope, transfer_binding,
};
use traffic_rewrite_agents::implementer::legacy;
pub(super) mod model;
pub(super) mod runtime;
pub(super) mod scheduler;

pub use model::RewriteWorkerMissingQuery;
pub(super) use traffic_rewrite_agents::implementer::legacy::AGENT_HANDLE_ENV;
pub use traffic_rewrite_agents::implementer::legacy::{
    RewriteWorkerConfirmOptions, RewriteWorkerTransferOptions,
};

#[cfg(test)]
pub(super) fn gate_envelope(
    target_root: &std::path::Path,
    state: &RewriteState,
    requested_scope: Option<RewriteWorkScope>,
) -> RewriteActionEnvelope {
    action::envelope(
        target_root,
        state,
        implementation_action(target_root, state, requested_scope),
    )
}

pub(super) fn implementation_action(
    target_root: &std::path::Path,
    state: &RewriteState,
    requested_scope: Option<RewriteWorkScope>,
) -> RewriteAction {
    let scope = active_scope(state).expect("implementation phase requires a work scope");
    let issue = issue_for_scope(state, &scope)
        .cloned()
        .expect("implementation phase requires an issue");
    let worker = dispatch_view(state, scope.clone(), requested_scope.clone());
    let summary = match worker.state {
        RewriteWorkerDispatchState::Confirmed => issue.summary.clone(),
        dispatch_state => {
            let operation = match dispatch_state {
                RewriteWorkerDispatchState::DispatchRequired => "dispatch the dedicated subagent",
                _ => "resume the bound subagent",
            };
            let selection = requested_scope
                .as_ref()
                .map(|requested| format!(" before selecting {}", requested.label()))
                .unwrap_or_default();
            format!(
                "{operation} for {}; execute commands.confirm_worker for this dispatch{selection}, then follow the returned action. {}",
                scope.label(),
                issue.summary
            )
        }
    };
    let confirm_worker = confirmation_command(target_root, &worker);
    let report_worker = runtime::report_command_for_scope(target_root, state, &scope, false);
    let acceptance = action::next_command(target_root);
    RewriteAction::ImplementationRequired {
        summary,
        execution_mode: None,
        issue,
        worker,
        confirm_worker,
        report_worker,
        acceptance,
    }
}

pub(super) fn state_action(target_root: &std::path::Path, state: &RewriteState) -> RewriteAction {
    scheduler::after_dispatch(target_root, state)
}

pub(super) fn confirmation_command(
    target_root: &std::path::Path,
    view: &RewriteWorkerDispatchView,
) -> Option<RewriteCommandSpec> {
    (view.state != RewriteWorkerDispatchState::Confirmed).then(|| {
        let mut argv = vec!["worker".into(), "confirm".into()];
        match &view.work_scope {
            RewriteWorkScope::Api { api } => argv.extend(["--api".into(), api.clone()]),
        }
        let mut env = vec!["BACKEND_REWRITE_WORKER_WORKTREE".into()];
        legacy::command_handle(&mut argv, &mut env, view.agent_handle.as_deref());
        action::command(target_root, argv, env)
    })
}

#[cfg(test)]
pub(super) fn current_is_confirmed(state: &RewriteState) -> bool {
    active_scope(state).is_some_and(|scope| is_confirmed(state, &scope))
}

pub(super) fn ensure_api_confirmed(state: &RewriteState, api: &str, operation: &str) -> Result<()> {
    let scoped = super::api_selector::scoped(state, api)?;
    let scope = super::api_selector::work_scope(state, api);
    ensure_scope_confirmed(&scoped, &scope, operation)
}

pub(super) fn ensure_scope_confirmed(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    operation: &str,
) -> Result<()> {
    let scope = super::api_selector::canonical_scope(state, scope);
    ensure!(
        is_confirmed(state, &scope),
        "{} requires a confirmed dedicated subagent dispatch before {operation}; ask the workflow coordinator to inspect scoped status and follow its returned action. When offered, execute action.commands.confirm_worker or the pooled implementer confirmation, then retry this operation. If status requests a changed-engine Replay, finish that refresh first; the existing failed attempt is retained and a fresh failure issues a new dispatch",
        scope.label()
    );
    Ok(())
}

pub fn confirm(options: RewriteWorkerConfirmOptions) -> Result<RewriteActionEnvelope> {
    crate::purpose::require_work_branch(&options.target_root)?;
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    legacy::validate_confirmation(&options)?;

    let store = RewriteStore::new(&target_root)?;
    let _lock = events::lock(&target_root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    ensure!(
        state.implementers.is_none(),
        "pooled workflows require implementer confirm with the exact batch identity"
    );
    let scope = super::api_selector::canonical_scope(&state, &options.work_scope);
    ensure!(
        runtime::scopes(&state).contains(&scope),
        "{} is not implementation_required",
        scope.label()
    );
    let expected_dispatch_id = dispatch_id(&state, &scope);

    let new_dispatch = state
        .worker_bindings
        .get(&scope.binding_key())
        .is_none_or(|b| b.confirmed_dispatch_id != expected_dispatch_id);
    let mut changed = confirm_binding(
        &mut state,
        &scope,
        &expected_dispatch_id,
        &options.agent_handle,
        options.agent_name,
    )?;
    changed |= super::review::bind(
        &target_root,
        &mut state,
        &scope,
        options.worktree.as_deref(),
        new_dispatch,
    )?;
    if changed {
        events::publish(&target_root, &state, &scope)?;
    }
    drop(_lock);
    runtime::current_envelope(&target_root)
}

pub fn transfer(options: RewriteWorkerTransferOptions) -> Result<RewriteActionEnvelope> {
    crate::purpose::require_work_branch(&options.target_root)?;
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let authorization = legacy::validate_transfer(&options)?;

    let store = RewriteStore::new(&target_root)?;
    let _lock = events::lock(&target_root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scope = identity::scope_for_handle(&state, &options.previous_agent_handle)?;

    transfer_binding(
        &mut state,
        &scope,
        &options.agent_handle,
        options.agent_name,
        options.reason,
        authorization,
    )?;
    events::publish(&target_root, &state, &scope)?;
    drop(_lock);
    runtime::current_envelope(&target_root)
}

fn active_scope(state: &RewriteState) -> Option<RewriteWorkScope> {
    (state.phase == RewritePhase::ImplementationRequired && state.active_issue.is_some())
        .then(|| super::api_selector::work_scope(state, &state.api))
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn confirm_current_for_test(state: &mut RewriteState) {
    let scope = active_scope(state).unwrap();
    let dispatch_id = dispatch_id(state, &scope);
    let handle = format!("test-subagent-handle:{}", scope.binding_key());
    confirm_binding(state, &scope, &dispatch_id, &handle, None).unwrap();
    runtime::record_running_for_test(state, &scope);
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn integrate_current_for_test(state: &mut RewriteState) {
    confirm_current_for_test(state);
    let scope = active_scope(state).unwrap();
    let value = state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    value.activity = model::RewriteWorkerActivity::Integrated;
    value.handoff_id = Some("tested-handoff".into());
    value.integrated_target_fingerprint = Some("integrated-test-target".into());
}

#[cfg(test)]
#[path = "worker_tests.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "worker/transfer_tests.rs"]
mod transfer_tests;
