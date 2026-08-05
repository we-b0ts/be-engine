use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteCommandSpec, RewritePhase, RewriteState,
    RewriteWorkerBinding, RewriteWorkerBlockingReason, RewriteWorkerDispatchState,
    RewriteWorkerDispatchView,
};
use super::store::RewriteStore;
use super::{action, evidence, fingerprint};

#[derive(Debug, Clone)]
pub struct RewriteWorkerConfirmOptions {
    pub target_root: std::path::PathBuf,
    pub dispatch_id: String,
    pub agent_handle: String,
    pub agent_name: Option<String>,
}

pub(super) const AGENT_HANDLE_ENV: &str = "BACKEND_REWRITE_SUBAGENT_HANDLE";

pub(super) fn gate_envelope(
    target_root: &std::path::Path,
    state: &RewriteState,
    requested_api: Option<String>,
) -> RewriteActionEnvelope {
    action::envelope(
        state,
        implementation_action(target_root, state, requested_api),
    )
}

pub(super) fn implementation_action(
    target_root: &std::path::Path,
    state: &RewriteState,
    requested_api: Option<String>,
) -> RewriteAction {
    let issue = state
        .active_issue
        .clone()
        .expect("implementation phase requires an issue");
    let worker = dispatch_view(state, requested_api.clone());
    let summary = match (worker.state, requested_api) {
        (RewriteWorkerDispatchState::DispatchRequired, Some(requested)) => format!(
            "dispatch and confirm the dedicated subagent for API {} before selecting {requested}",
            state.api
        ),
        (RewriteWorkerDispatchState::ResumeRequired, Some(requested)) => format!(
            "resume and confirm the bound subagent for API {} before selecting {requested}",
            state.api
        ),
        (_, Some(requested)) => format!(
            "dedicated subagent confirmation for API {} is required before selecting {requested}",
            state.api
        ),
        (_, None) => issue.summary.clone(),
    };
    let confirm_worker = confirmation_command(target_root, &worker);
    RewriteAction::ImplementationRequired {
        summary,
        issue,
        worker,
        confirm_worker,
        evidence_commands: evidence::commands(target_root, state),
        acceptance: action::next_command_for_api(target_root, &state.api),
    }
}

pub(super) fn dispatch_view(
    state: &RewriteState,
    requested_api: Option<String>,
) -> RewriteWorkerDispatchView {
    let dispatch_id = dispatch_id(state);
    let dispatch_state = dispatch_state(state, &dispatch_id);
    RewriteWorkerDispatchView {
        binding_id: binding_id(state),
        dispatch_id,
        state: dispatch_state,
        blocking_reason: (dispatch_state != RewriteWorkerDispatchState::Confirmed)
            .then_some(RewriteWorkerBlockingReason::WorkerDispatchUnconfirmed),
        requested_api,
        agent_name: state
            .worker_bindings
            .get(&state.api)
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
    state.phase == RewritePhase::ImplementationRequired
        && dispatch_state(state, &dispatch_id(state)) == RewriteWorkerDispatchState::Confirmed
}

pub(super) fn ensure_current_confirmed(state: &RewriteState) -> Result<()> {
    ensure!(
        current_is_confirmed(state),
        "API {} cannot be parked until its dedicated subagent dispatch is confirmed",
        state.api
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
    ensure!(
        state.phase == RewritePhase::ImplementationRequired,
        "API {} is in {:?}, not implementation_required",
        state.api,
        state.phase
    );
    let expected_dispatch_id = dispatch_id(&state);
    ensure!(
        options.dispatch_id == expected_dispatch_id,
        "worker dispatch id is stale; inspect `backend-rewrite status --api '{}'`",
        state.api
    );

    let changed = confirm_binding(
        &mut state,
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

fn confirm_binding(
    state: &mut RewriteState,
    expected_dispatch_id: &str,
    agent_handle: &str,
    agent_name: Option<String>,
) -> Result<bool> {
    let handle_fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", agent_handle]);
    let active_api = state.api.clone();
    let mut changed = false;
    match state.worker_bindings.get_mut(&active_api) {
        Some(binding) => {
            ensure!(
                binding.agent_handle_fingerprint == handle_fingerprint,
                "API {} is already bound to a different subagent handle; resume the stored handle or request explicit ownership transfer",
                active_api
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
                active_api,
                RewriteWorkerBinding {
                    agent_handle_fingerprint: handle_fingerprint,
                    agent_name,
                    confirmed_dispatch_id: expected_dispatch_id.to_string(),
                },
            );
            changed = true;
        }
    }
    Ok(changed)
}

fn binding_id(state: &RewriteState) -> String {
    fingerprint::id(&[
        "rewrite-worker-binding-v1",
        state.workflow_id.as_str(),
        state.api.as_str(),
    ])
}

fn dispatch_id(state: &RewriteState) -> String {
    let issue = state
        .active_issue
        .as_ref()
        .expect("implementation phase requires an issue");
    let attempt = issue.attempt.to_string();
    fingerprint::id(&[
        "rewrite-worker-dispatch-v1",
        state.workflow_id.as_str(),
        state.api.as_str(),
        issue.id.as_str(),
        attempt.as_str(),
        issue.observed_target_fingerprint.as_str(),
    ])
}

fn dispatch_state(state: &RewriteState, dispatch_id: &str) -> RewriteWorkerDispatchState {
    match state.worker_bindings.get(&state.api) {
        None => RewriteWorkerDispatchState::DispatchRequired,
        Some(binding) if binding.confirmed_dispatch_id == dispatch_id => {
            RewriteWorkerDispatchState::Confirmed
        }
        Some(_) => RewriteWorkerDispatchState::ResumeRequired,
    }
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
    let dispatch_id = dispatch_id(state);
    confirm_binding(state, &dispatch_id, "test-subagent-handle", None).unwrap();
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::rewrite::model::{RewriteIssue, RewriteIssueKind, RewriteIssueOwner};

    #[test]
    fn one_handle_is_bound_and_resumed_for_later_dispatches() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(issue("issue-a", 1, "target-a"));

        let initial = dispatch_view(&state, None);
        assert_eq!(initial.state, RewriteWorkerDispatchState::DispatchRequired);
        assert!(
            confirm_binding(
                &mut state,
                &initial.dispatch_id,
                "runtime-handle-a",
                Some("friends-worker".to_string()),
            )
            .unwrap()
        );
        assert_eq!(
            dispatch_view(&state, None).state,
            RewriteWorkerDispatchState::Confirmed
        );
        assert!(
            !serde_json::to_string(&dispatch_view(&state, None))
                .unwrap()
                .contains("runtime-handle-a")
        );

        state.active_issue = Some(issue("issue-b", 2, "target-b"));
        let later = dispatch_view(&state, None);
        assert_eq!(later.state, RewriteWorkerDispatchState::ResumeRequired);
        assert!(
            confirm_binding(
                &mut state,
                &later.dispatch_id,
                "different-runtime-handle",
                None,
            )
            .is_err()
        );
        assert!(
            confirm_binding(
                &mut state,
                &later.dispatch_id,
                "runtime-handle-a",
                Some("renamed-friends-worker".to_string()),
            )
            .unwrap()
        );
        let confirmed = dispatch_view(&state, None);
        assert_eq!(confirmed.state, RewriteWorkerDispatchState::Confirmed);
        assert_eq!(
            confirmed.agent_name.as_deref(),
            Some("renamed-friends-worker")
        );
    }

    #[test]
    fn cross_api_selection_returns_a_structured_worker_dispatch_gate() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(issue("issue-response", 1, "target-a"));
        let target = Path::new("/target");

        let blocked = serde_json::to_value(gate_envelope(
            target,
            &state,
            Some("POST /other".to_string()),
        ))
        .unwrap();
        assert_eq!(blocked["action"]["kind"], "implementation_required");
        assert_eq!(
            blocked["action"]["details"]["worker"]["state"],
            "dispatch_required"
        );
        assert_eq!(
            blocked["action"]["details"]["worker"]["blocking_reason"],
            "worker_dispatch_unconfirmed"
        );
        assert_eq!(
            blocked["action"]["details"]["worker"]["requested_api"],
            "POST /other"
        );
        assert_eq!(
            blocked.pointer("/action/commands/confirm_worker/required_env_names/0"),
            Some(&serde_json::json!(AGENT_HANDLE_ENV))
        );

        confirm_current_for_test(&mut state);
        let confirmed = serde_json::to_value(action::for_state(target, &state)).unwrap();
        assert_eq!(
            confirmed["action"]["details"]["worker"]["state"],
            "confirmed"
        );
        assert!(
            confirmed
                .pointer("/action/commands/confirm_worker")
                .is_none()
        );
    }

    fn issue(id: &str, attempt: u64, target_fingerprint: &str) -> RewriteIssue {
        RewriteIssue {
            id: id.to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "implementation differs".to_string(),
            pointer_pattern: None,
            representative: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: target_fingerprint.to_string(),
            attempt,
            comparison_observation: None,
        }
    }
}
