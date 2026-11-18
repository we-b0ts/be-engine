//! Durable worker binding and dispatch identities.
use crate::{api_selector, fingerprint};
use anyhow::{Context, Result, ensure};
use traffic_rewrite_model::rewrite::{
    RewriteIssue, RewritePhase, RewriteState, RewriteWorkScope, RewriteWorkerActivity,
    RewriteWorkerBinding, RewriteWorkerBlockingReason, RewriteWorkerDispatchState,
    RewriteWorkerDispatchView, RewriteWorkerTransferAuthorization, RewriteWorkerTransferRecord,
    inventory::is_skipped,
};
pub fn dispatch_view(
    state: &RewriteState,
    scope: RewriteWorkScope,
    requested_scope: Option<RewriteWorkScope>,
) -> RewriteWorkerDispatchView {
    let RewriteWorkScope::Api { api } = scope;
    let scope = RewriteWorkScope::Api {
        api: api_selector::public_api(&api).into(),
    };
    let dispatch_id = dispatch_id(state, &scope);
    let dispatch_state = dispatch_state(state, &scope, &dispatch_id);
    let binding_key = scope.binding_key();
    RewriteWorkerDispatchView {
        binding_id: binding_id(state, &scope),
        dispatch_id,
        agent_handle: state
            .worker_bindings
            .get(&binding_key)
            .and_then(|binding| binding.agent_handle.clone()),
        work_scope: scope,
        state: dispatch_state,
        first_bound_at: state
            .worker_bindings
            .get(&binding_key)
            .and_then(|binding| binding.first_bound_at.clone()),
        last_integrated_at: state
            .worker_bindings
            .get(&binding_key)
            .and_then(|binding| binding.last_integrated_at.clone()),
        last_integrated_commit: state
            .worker_bindings
            .get(&binding_key)
            .and_then(|binding| binding.last_integrated_commit.clone()),
        blocking_reason: (dispatch_state != RewriteWorkerDispatchState::Confirmed)
            .then_some(RewriteWorkerBlockingReason::WorkerDispatchUnconfirmed),
        requested_api: requested_scope.map(|scope| match scope {
            RewriteWorkScope::Api { api } => api,
        }),
        agent_name: state
            .worker_bindings
            .get(&binding_key)
            .and_then(|binding| binding.agent_name.clone()),
    }
}

pub fn confirm_binding(
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
            (state.implementers.is_none()
                && key != &binding_key
                && binding.agent_handle_fingerprint == handle_fingerprint)
                || binding.expert.as_ref().is_some_and(|expert| {
                    expert.agent_handle_fingerprint.as_ref() == Some(&handle_fingerprint)
                })
        }),
        "subagent handle is already dedicated to another work item in this workflow"
    );
    let mut changed = false;
    match state.worker_bindings.get_mut(&binding_key) {
        Some(binding) => {
            ensure!(
                state.implementers.is_some()
                    || binding.agent_handle_fingerprint == handle_fingerprint,
                "{} is already bound to a different subagent handle; resume the stored handle or request explicit ownership transfer",
                scope.label()
            );
            if binding.agent_handle_fingerprint != handle_fingerprint {
                binding.agent_handle_fingerprint = handle_fingerprint.clone();
                binding.transfer_generation = binding.transfer_generation.saturating_add(1);
                changed = true;
            }
            if agent_name.is_some() && binding.agent_name != agent_name {
                binding.agent_name = agent_name;
                changed = true;
            }
            if binding.agent_handle.as_deref() != Some(agent_handle) {
                binding.agent_handle = Some(agent_handle.into());
                changed = true;
            }
            if binding.first_bound_at.is_none() {
                binding.first_bound_at = Some(chrono::Utc::now().to_rfc3339());
                changed = true;
            }
            if binding.confirmed_dispatch_id != expected_dispatch_id {
                binding.confirmed_dispatch_id = expected_dispatch_id.to_string();
                binding.observation = None;
                changed = true;
            }
        }
        None => {
            state.worker_bindings.insert(
                binding_key,
                RewriteWorkerBinding {
                    agent_handle: Some(agent_handle.into()),
                    agent_handle_fingerprint: handle_fingerprint,
                    agent_name,
                    confirmed_dispatch_id: expected_dispatch_id.to_string(),
                    first_bound_at: Some(chrono::Utc::now().to_rfc3339()),
                    last_integrated_at: None,
                    last_integrated_commit: None,
                    expert: None,
                    transfer_generation: 0,
                    rework_generation: 0,
                    last_transfer: None,
                    observation: None,
                    review_assignment: None,
                    review_report: None,
                },
            );
            changed = true;
        }
    }
    Ok(changed)
}

pub fn transfer_binding(
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
    agent_handle: &str,
    agent_name: Option<String>,
    reason: String,
    authorization: RewriteWorkerTransferAuthorization,
) -> Result<()> {
    let binding_key = scope.binding_key();
    let new_fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", agent_handle]);
    ensure!(
        !state.worker_bindings.iter().any(|(key, binding)| {
            key != &binding_key && binding.agent_handle_fingerprint == new_fingerprint
                || binding.expert.as_ref().is_some_and(|expert| {
                    expert.agent_handle_fingerprint.as_ref() == Some(&new_fingerprint)
                })
        }),
        "replacement subagent handle is already bound to another work item in this workflow"
    );
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
    binding.agent_handle = Some(agent_handle.into());
    binding.rework_generation = binding
        .rework_generation
        .checked_add(1)
        .context("worker rework generation overflow")?;
    binding.transfer_generation = binding.transfer_generation.saturating_add(1);
    binding.last_transfer = Some(RewriteWorkerTransferRecord {
        previous_agent_handle_fingerprint: previous_fingerprint,
        reason,
        transferred_at: chrono::Utc::now().to_rfc3339(),
        authorization,
    });
    binding.observation = None;
    binding.review_report = None;
    let expected_dispatch_id = dispatch_id(state, scope);
    state
        .worker_bindings
        .get_mut(&binding_key)
        .unwrap()
        .confirmed_dispatch_id = expected_dispatch_id;
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

pub fn dispatch_id(state: &RewriteState, scope: &RewriteWorkScope) -> String {
    let issue = issue_for_scope(state, scope).expect("implementation phase requires an issue");
    let binding_key = scope.binding_key();
    let attempt = issue.attempt.to_string();
    let route_issues = match scope {
        RewriteWorkScope::Api { api } if !api.contains(' ') => {
            let mut issues = std::iter::once(&state.active_slice)
                .chain(state.parked_slices.values())
                .filter(|slice| {
                    api_selector::route(&slice.api) == api
                        && !is_skipped(state, &slice.api)
                        && slice.phase == RewritePhase::ImplementationRequired
                })
                .filter_map(|slice| {
                    slice
                        .active_issue
                        .as_ref()
                        .map(|issue| (&slice.api, &issue.id))
                })
                .collect::<Vec<_>>();
            issues.sort();
            serde_json::to_string(&issues).expect("route issues serialize")
        }
        _ => issue.id.clone(),
    };
    let original = fingerprint::id(&[
        "rewrite-worker-dispatch-v1",
        state.workflow_id.as_str(),
        binding_key.as_str(),
        route_issues.as_str(),
        attempt.as_str(),
        issue.observed_target_fingerprint.as_str(),
    ]);
    let original = if state.implementers.is_some() {
        fingerprint::id(&[
            "implementer-recording-dispatch-v1",
            &original,
            &state.recording_run_id,
        ])
    } else {
        original
    };
    let generation = state
        .worker_bindings
        .get(&binding_key)
        .map_or(0, |binding| binding.rework_generation);
    if generation == 0 {
        original
    } else {
        fingerprint::id(&[
            "rewrite-worker-rework-v1",
            &original,
            &generation.to_string(),
        ])
    }
}

fn dispatch_state(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    dispatch_id: &str,
) -> RewriteWorkerDispatchState {
    match state.worker_bindings.get(&scope.binding_key()) {
        None => RewriteWorkerDispatchState::DispatchRequired,
        Some(binding) if binding.confirmed_dispatch_id == dispatch_id => {
            if super::feedback::observation(state, scope)
                .is_some_and(|observation| observation.activity == RewriteWorkerActivity::Idle)
            {
                RewriteWorkerDispatchState::ResumeRequired
            } else {
                RewriteWorkerDispatchState::Confirmed
            }
        }
        Some(_) => RewriteWorkerDispatchState::ResumeRequired,
    }
}

pub fn issue_for_scope<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Option<&'a RewriteIssue> {
    match scope {
        RewriteWorkScope::Api { api } => {
            if api.contains(' ') {
                return if api == &state.api {
                    state.active_issue.as_ref()
                } else {
                    state
                        .parked_slices
                        .get(api)
                        .and_then(|slice| slice.active_issue.as_ref())
                };
            }
            let mut slices = std::iter::once(&state.active_slice)
                .chain(state.parked_slices.values())
                .filter(|slice| {
                    api_selector::route(&slice.api) == api
                        && !is_skipped(state, &slice.api)
                        && slice.phase == RewritePhase::ImplementationRequired
                        && slice.active_issue.is_some()
                })
                .collect::<Vec<_>>();
            slices.sort_by(|left, right| left.api.cmp(&right.api));
            slices.first().and_then(|slice| slice.active_issue.as_ref())
        }
    }
}

pub fn is_confirmed(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    issue_for_scope(state, scope).is_some()
        && dispatch_state(state, scope, &dispatch_id(state, scope))
            == RewriteWorkerDispatchState::Confirmed
}
