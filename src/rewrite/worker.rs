use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteCommandSpec, RewritePhase, RewriteState,
    RewriteWorkerBinding, RewriteWorkerBlockingReason, RewriteWorkerDispatchState,
    RewriteWorkerDispatchView, RewriteWorkerTransferRecord,
};
use super::process_output_model::RewriteWorkScope;
use super::store::RewriteStore;
use super::{action, evidence, fingerprint, inventory, process_outputs};
use crate::RecordingApi;

#[derive(Debug, Clone)]
pub struct RewriteWorkerConfirmOptions {
    pub target_root: std::path::PathBuf,
    pub dispatch_id: String,
    pub agent_handle: String,
    pub agent_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteWorkerTransferOptions {
    pub target_root: std::path::PathBuf,
    pub binding_id: String,
    pub agent_handle: String,
    pub agent_name: Option<String>,
    pub reason: String,
    pub caller_approved: bool,
}

pub(super) const AGENT_HANDLE_ENV: &str = "BACKEND_REWRITE_SUBAGENT_HANDLE";

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
    let (evidence_commands, acceptance) = match &scope {
        RewriteWorkScope::Api { api } => (
            evidence::commands(target_root, state),
            action::next_command_for_api(target_root, api),
        ),
        RewriteWorkScope::ProcessOutput { id } => (
            Vec::new(),
            action::next_command_for_process_output(target_root, id),
        ),
    };
    RewriteAction::ImplementationRequired {
        summary,
        issue,
        worker,
        confirm_worker,
        evidence_commands,
        acceptance,
    }
}

pub(super) fn state_action(target_root: &std::path::Path, state: &RewriteState) -> RewriteAction {
    let scope = active_scope(state).expect("implementation action requires a work scope");
    if is_confirmed(state, &scope) {
        if let Some(pending_api) = inventory::next_pending_api_for_concurrent_work(state) {
            return RewriteAction::AdvanceRequired {
                summary: format!(
                    "dedicated subagent for {} is confirmed; execute commands.advance to continue with pending API {pending_api}",
                    scope.label()
                ),
                command: action::next_command_for_api(target_root, pending_api),
            };
        }
        if let Some(id) = process_outputs::next_eligible_id(state) {
            return RewriteAction::AdvanceRequired {
                summary: format!(
                    "dedicated subagent for {} is confirmed; execute commands.advance to verify process output {id}",
                    scope.label()
                ),
                command: action::next_command_for_process_output(target_root, id),
            };
        }
    }
    implementation_action(target_root, state, None)
}

pub(super) fn dispatch_view(
    state: &RewriteState,
    scope: RewriteWorkScope,
    requested_scope: Option<RewriteWorkScope>,
) -> RewriteWorkerDispatchView {
    let dispatch_id = dispatch_id(state, &scope);
    let dispatch_state = dispatch_state(state, &scope, &dispatch_id);
    let binding_key = scope.binding_key();
    RewriteWorkerDispatchView {
        binding_id: binding_id(state, &scope),
        dispatch_id,
        work_scope: scope,
        state: dispatch_state,
        blocking_reason: (dispatch_state != RewriteWorkerDispatchState::Confirmed)
            .then_some(RewriteWorkerBlockingReason::WorkerDispatchUnconfirmed),
        requested_api: requested_scope.and_then(|scope| match scope {
            RewriteWorkScope::Api { api } => Some(api),
            RewriteWorkScope::ProcessOutput { .. } => None,
        }),
        agent_name: state
            .worker_bindings
            .get(&binding_key)
            .and_then(|binding| binding.agent_name.clone()),
    }
}

pub(super) fn confirmation_command(
    target_root: &std::path::Path,
    view: &RewriteWorkerDispatchView,
) -> Option<RewriteCommandSpec> {
    (view.state != RewriteWorkerDispatchState::Confirmed).then(|| {
        action::command(
            target_root,
            vec![
                "worker".to_string(),
                "confirm".to_string(),
                view.dispatch_id.clone(),
            ],
            vec![AGENT_HANDLE_ENV.to_string()],
        )
    })
}

pub(super) fn current_is_confirmed(state: &RewriteState) -> bool {
    active_scope(state).is_some_and(|scope| is_confirmed(state, &scope))
}

pub(super) fn active_dispatch_required(state: &RewriteState) -> bool {
    active_scope(state).is_some() && !current_is_confirmed(state)
}

pub(super) fn ensure_current_confirmed(state: &RewriteState) -> Result<()> {
    let scope = RewriteWorkScope::Api {
        api: state.api.clone(),
    };
    ensure!(
        is_confirmed(state, &scope),
        "API {} cannot be parked until its dedicated subagent dispatch is confirmed",
        state.api
    );
    Ok(())
}

pub(super) fn ensure_api_confirmed(state: &RewriteState, api: &str, operation: &str) -> Result<()> {
    let requested_api = api.parse::<RecordingApi>()?;
    let scoped = inventory::scoped(state, Some(&requested_api))?;
    let scope = RewriteWorkScope::Api {
        api: api.to_string(),
    };
    ensure!(
        is_confirmed(&scoped, &scope),
        "API {api} requires a confirmed dedicated subagent dispatch before {operation}; inspect its scoped status and execute action.commands.confirm_worker"
    );
    Ok(())
}

pub fn confirm(options: RewriteWorkerConfirmOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    validate_identity("subagent handle", &options.agent_handle, 4_096)?;
    if let Some(name) = options.agent_name.as_deref() {
        validate_identity("subagent name", name, 128)?;
    }

    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scope = active_scope(&state).context("rewrite workflow has no implementation work item")?;
    ensure!(
        issue_for_scope(&state, &scope).is_some(),
        "{} is not implementation_required",
        scope.label()
    );
    let expected_dispatch_id = dispatch_id(&state, &scope);
    ensure!(
        options.dispatch_id == expected_dispatch_id,
        "worker dispatch id is stale; inspect the scoped backend-rewrite status for {}",
        scope.label()
    );

    let changed = confirm_binding(
        &mut state,
        &scope,
        &expected_dispatch_id,
        &options.agent_handle,
        options.agent_name,
    )?;
    if changed {
        state.bump();
        store.save(&state)?;
    }
    Ok(action::for_state(&target_root, &state))
}

pub fn transfer(options: RewriteWorkerTransferOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    validate_identity("subagent handle", &options.agent_handle, 4_096)?;
    validate_identity("ownership transfer reason", &options.reason, 512)?;
    if let Some(name) = options.agent_name.as_deref() {
        validate_identity("subagent name", name, 128)?;
    }
    ensure!(
        options.caller_approved,
        "worker ownership transfer requires explicit caller approval"
    );

    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scope = active_scope(&state).context("rewrite workflow has no implementation work item")?;
    ensure!(
        issue_for_scope(&state, &scope).is_some(),
        "{} is not implementation_required",
        scope.label()
    );
    ensure!(
        options.binding_id == binding_id(&state, &scope),
        "worker binding id is stale; inspect the scoped backend-rewrite status for {}",
        scope.label()
    );

    transfer_binding(
        &mut state,
        &scope,
        &options.agent_handle,
        options.agent_name,
        options.reason,
    )?;
    state.bump();
    store.save(&state)?;
    Ok(action::for_state(&target_root, &state))
}

fn confirm_binding(
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
    expected_dispatch_id: &str,
    agent_handle: &str,
    agent_name: Option<String>,
) -> Result<bool> {
    let handle_fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", agent_handle]);
    let binding_key = scope.binding_key();
    ensure!(
        !state.worker_bindings.iter().any(|(key, binding)| {
            key != &binding_key && binding.agent_handle_fingerprint == handle_fingerprint
        }),
        "subagent handle is already dedicated to another work item in this workflow"
    );
    let mut changed = false;
    match state.worker_bindings.get_mut(&binding_key) {
        Some(binding) => {
            ensure!(
                binding.agent_handle_fingerprint == handle_fingerprint,
                "{} is already bound to a different subagent handle; resume the stored handle or request explicit ownership transfer",
                scope.label()
            );
            if agent_name.is_some() && binding.agent_name != agent_name {
                binding.agent_name = agent_name;
                changed = true;
            }
            if binding.confirmed_dispatch_id != expected_dispatch_id {
                binding.confirmed_dispatch_id = expected_dispatch_id.to_string();
                changed = true;
            }
        }
        None => {
            state.worker_bindings.insert(
                binding_key,
                RewriteWorkerBinding {
                    agent_handle_fingerprint: handle_fingerprint,
                    agent_name,
                    confirmed_dispatch_id: expected_dispatch_id.to_string(),
                    transfer_generation: 0,
                    last_transfer: None,
                },
            );
            changed = true;
        }
    }
    Ok(changed)
}

fn transfer_binding(
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
    agent_handle: &str,
    agent_name: Option<String>,
    reason: String,
) -> Result<()> {
    let binding_key = scope.binding_key();
    let new_fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", agent_handle]);
    ensure!(
        !state.worker_bindings.iter().any(|(key, binding)| {
            key != &binding_key && binding.agent_handle_fingerprint == new_fingerprint
        }),
        "replacement subagent handle is already bound to another work item in this workflow"
    );
    let expected_dispatch_id = dispatch_id(state, scope);
    let binding = state
        .worker_bindings
        .get_mut(&binding_key)
        .context("work item has no existing worker ownership to transfer")?;
    ensure!(
        binding.agent_handle_fingerprint != new_fingerprint,
        "replacement subagent handle already owns this API; use worker confirm"
    );
    let previous_fingerprint =
        std::mem::replace(&mut binding.agent_handle_fingerprint, new_fingerprint);
    binding.agent_name = agent_name;
    binding.confirmed_dispatch_id = expected_dispatch_id;
    binding.transfer_generation = binding.transfer_generation.saturating_add(1);
    binding.last_transfer = Some(RewriteWorkerTransferRecord {
        previous_agent_handle_fingerprint: previous_fingerprint,
        reason,
        transferred_at: chrono::Utc::now().to_rfc3339(),
    });
    Ok(())
}

fn binding_id(state: &RewriteState, scope: &RewriteWorkScope) -> String {
    let binding_key = scope.binding_key();
    let binding = state.worker_bindings.get(&binding_key);
    let handle = binding
        .map(|binding| binding.agent_handle_fingerprint.as_str())
        .unwrap_or("unbound");
    let generation = binding
        .map(|binding| binding.transfer_generation.to_string())
        .unwrap_or_else(|| "0".to_string());
    fingerprint::id(&[
        "rewrite-worker-binding-v2",
        state.workflow_id.as_str(),
        binding_key.as_str(),
        handle,
        generation.as_str(),
    ])
}

fn dispatch_id(state: &RewriteState, scope: &RewriteWorkScope) -> String {
    let issue = issue_for_scope(state, scope).expect("implementation phase requires an issue");
    let binding_key = scope.binding_key();
    let attempt = issue.attempt.to_string();
    fingerprint::id(&[
        "rewrite-worker-dispatch-v1",
        state.workflow_id.as_str(),
        binding_key.as_str(),
        issue.id.as_str(),
        attempt.as_str(),
        issue.observed_target_fingerprint.as_str(),
    ])
}

fn dispatch_state(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    dispatch_id: &str,
) -> RewriteWorkerDispatchState {
    match state.worker_bindings.get(&scope.binding_key()) {
        None => RewriteWorkerDispatchState::DispatchRequired,
        Some(binding) if binding.confirmed_dispatch_id == dispatch_id => {
            RewriteWorkerDispatchState::Confirmed
        }
        Some(_) => RewriteWorkerDispatchState::ResumeRequired,
    }
}

fn active_scope(state: &RewriteState) -> Option<RewriteWorkScope> {
    process_outputs::active_scope(state).or_else(|| {
        (state.phase == RewritePhase::ImplementationRequired && state.active_issue.is_some()).then(
            || RewriteWorkScope::Api {
                api: state.api.clone(),
            },
        )
    })
}

fn issue_for_scope<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Option<&'a super::model::RewriteIssue> {
    match scope {
        RewriteWorkScope::Api { api } if api == &state.api => state.active_issue.as_ref(),
        RewriteWorkScope::Api { api } => state
            .parked_slices
            .get(api)
            .and_then(|slice| slice.active_issue.as_ref()),
        RewriteWorkScope::ProcessOutput { .. } => process_outputs::issue_for_scope(state, scope),
    }
}

fn is_confirmed(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    issue_for_scope(state, scope).is_some()
        && dispatch_state(state, scope, &dispatch_id(state, scope))
            == RewriteWorkerDispatchState::Confirmed
}

fn validate_identity(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && !value.contains(['\r', '\n']),
        "{label} must be a non-empty single line"
    );
    ensure!(value.len() <= max_bytes, "{label} is too long");
    Ok(())
}

#[cfg(test)]
pub(super) fn confirm_current_for_test(state: &mut RewriteState) {
    let scope = active_scope(state).unwrap();
    let dispatch_id = dispatch_id(state, &scope);
    let handle = format!("test-subagent-handle:{}", scope.binding_key());
    confirm_binding(state, &scope, &dispatch_id, &handle, None).unwrap();
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
