use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteCommandSpec, RewritePhase, RewriteState,
    RewriteWorkerBinding, RewriteWorkerBlockingReason, RewriteWorkerDispatchState,
    RewriteWorkerDispatchView, RewriteWorkerTransferRecord,
};
use super::store::RewriteStore;
use super::{action, evidence, fingerprint, inventory};
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
    requested_api: Option<String>,
) -> RewriteActionEnvelope {
    action::envelope(
        target_root,
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

pub(super) fn state_action(target_root: &std::path::Path, state: &RewriteState) -> RewriteAction {
    if current_is_confirmed(state)
        && let Some(pending_api) = inventory::next_pending_api_for_concurrent_work(state)
    {
        return RewriteAction::AdvanceRequired {
            summary: format!(
                "dedicated subagent for API {} is confirmed; advance pending API {pending_api} before waiting",
                state.api
            ),
            command: action::next_command_for_api(target_root, pending_api),
        };
    }
    implementation_action(target_root, state, None)
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

pub(super) fn ensure_api_confirmed(state: &RewriteState, api: &str, operation: &str) -> Result<()> {
    let requested_api = api.parse::<RecordingApi>()?;
    let scoped = inventory::scoped(state, Some(&requested_api))?;
    ensure!(
        current_is_confirmed(&scoped),
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
    ensure!(
        state.phase == RewritePhase::ImplementationRequired,
        "API {} is in {:?}, not implementation_required",
        state.api,
        state.phase
    );
    ensure!(
        options.binding_id == binding_id(&state),
        "worker binding id is stale; inspect `backend-rewrite status --api '{}'`",
        state.api
    );

    transfer_binding(
        &mut state,
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
    expected_dispatch_id: &str,
    agent_handle: &str,
    agent_name: Option<String>,
) -> Result<bool> {
    let handle_fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", agent_handle]);
    let active_api = state.api.clone();
    ensure!(
        !state.worker_bindings.iter().any(|(api, binding)| {
            api != &active_api && binding.agent_handle_fingerprint == handle_fingerprint
        }),
        "subagent handle is already dedicated to another API in this workflow"
    );
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
    agent_handle: &str,
    agent_name: Option<String>,
    reason: String,
) -> Result<()> {
    let active_api = state.api.clone();
    let new_fingerprint = fingerprint::id(&["rewrite-subagent-handle-v1", agent_handle]);
    ensure!(
        !state.worker_bindings.iter().any(|(api, binding)| {
            api != &active_api && binding.agent_handle_fingerprint == new_fingerprint
        }),
        "replacement subagent handle is already bound to another API in this workflow"
    );
    let expected_dispatch_id = dispatch_id(state);
    let binding = state
        .worker_bindings
        .get_mut(&active_api)
        .context("API has no existing worker ownership to transfer")?;
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

fn binding_id(state: &RewriteState) -> String {
    let binding = state.worker_bindings.get(&state.api);
    let handle = binding
        .map(|binding| binding.agent_handle_fingerprint.as_str())
        .unwrap_or("unbound");
    let generation = binding
        .map(|binding| binding.transfer_generation.to_string())
        .unwrap_or_else(|| "0".to_string());
    fingerprint::id(&[
        "rewrite-worker-binding-v2",
        state.workflow_id.as_str(),
        state.api.as_str(),
        handle,
        generation.as_str(),
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
    let handle = format!("test-subagent-handle:{}", state.api);
    confirm_binding(state, &dispatch_id, &handle, None).unwrap();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::*;
    use crate::ResponseRuleKind;
    use crate::rewrite::model::{
        RewriteApiProgress, RewriteApiStatus, RewriteIssue, RewriteIssueKind, RewriteIssueOwner,
    };
    use crate::rewrite::{
        RewriteContext, RewriteDependencyOwnership, RewriteDependencyRulePlanOptions,
        RewriteDependencyRuleSelector, RewriteRecorderCapturePlanOptions, RewriteRouteCause,
        RewriteRouteOptions, RewriteRulePlanOptions,
    };

    #[test]
    fn diagnostic_entrypoints_require_worker_confirmation_without_mutating_state() {
        let target = configured_target();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = implementation_state_with_inventory(false);
        let query_id = evidence::commands(target.path(), &state)[0]
            .query_id
            .clone();
        let evidence_id = evidence::query(target.path(), &state, &query_id)
            .unwrap()
            .evidence_id;
        store.save(&state).unwrap();
        let original = serde_json::to_value(&state).unwrap();
        let context = || RewriteContext {
            target_root: target.path().to_path_buf(),
        };

        assert_confirmation_error(
            super::super::query_rewrite_evidence(context(), &query_id).unwrap_err(),
            "querying evidence",
        );
        assert_confirmation_error(
            super::super::plan_rewrite_rule(
                context(),
                RewriteRulePlanOptions {
                    evidence_id: evidence_id.clone(),
                    kind: ResponseRuleKind::Uuid,
                    json_pointer: Some("/request_id".to_string()),
                    source_evidence: Some("src/id.rs:new".to_string()),
                    source_example: None,
                    target_example: None,
                },
            )
            .unwrap_err(),
            "planning a response rule",
        );
        assert_confirmation_error(
            super::super::plan_rewrite_dependency_rule(
                context(),
                RewriteDependencyRulePlanOptions {
                    evidence_id: evidence_id.clone(),
                    ownership: RewriteDependencyOwnership::ProcessOwned,
                    name: Some("cache-read".to_string()),
                    source_evidence: Some("src/cache.rs:read".to_string()),
                    selector: RewriteDependencyRuleSelector::RedisGet {
                        ports: vec![6379],
                        keys: vec!["cache:key".to_string()],
                        initial_load_timeout_ms: 60_000,
                    },
                },
            )
            .unwrap_err(),
            "planning a dependency rule",
        );
        assert_confirmation_error(
            super::super::plan_rewrite_recorder_capture(
                context(),
                RewriteRecorderCapturePlanOptions {
                    evidence_id: evidence_id.clone(),
                    endpoint: "cache.example.com:6379".to_string(),
                    source_evidence: "src/cache.rs:read".to_string(),
                },
            )
            .unwrap_err(),
            "planning recorder capture",
        );
        assert_confirmation_error(
            super::super::route_rewrite(RewriteRouteOptions {
                target_root: target.path().to_path_buf(),
                cause: RewriteRouteCause::SourceChange {
                    required_change: "refresh the source baseline".to_string(),
                },
                evidence_id,
                source_ref: "SourceService.java:read".to_string(),
            })
            .unwrap_err(),
            "routing the issue",
        );

        let persisted = store.load().unwrap().unwrap();
        assert_eq!(serde_json::to_value(&persisted).unwrap(), original);
        confirm_current_for_test(&mut state);
        store.save(&state).unwrap();
        super::super::query_rewrite_evidence(context(), &query_id).unwrap();
    }

    #[test]
    fn diagnostic_confirmation_follows_the_parked_evidence_owner() {
        let target = configured_target();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = implementation_state_with_inventory(true);
        confirm_current_for_test(&mut state);
        inventory::activate_requested(
            &mut state,
            Some(&"POST /other".parse::<RecordingApi>().unwrap()),
        )
        .unwrap();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(issue("issue-b", 1, "target-b"));
        confirm_current_for_test(&mut state);
        let parked = state.parked_slices.get_mut("GET /api").unwrap();
        parked.active_issue = Some(issue("issue-a-resumed", 2, "target-a-2"));
        let scoped =
            inventory::scoped(&state, Some(&"GET /api".parse::<RecordingApi>().unwrap())).unwrap();
        let query_id = evidence::commands(target.path(), &scoped)[0]
            .query_id
            .clone();
        store.save(&state).unwrap();

        let error = super::super::query_rewrite_evidence(
            RewriteContext {
                target_root: target.path().to_path_buf(),
            },
            &query_id,
        )
        .unwrap_err();
        assert_confirmation_error(error, "querying evidence");
        assert!(
            super::super::query_rewrite_evidence(
                RewriteContext {
                    target_root: target.path().to_path_buf(),
                },
                &evidence::commands(target.path(), &state)[0].query_id,
            )
            .is_ok()
        );
    }

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
    fn explicit_transfer_replaces_one_owner_and_confirms_the_current_dispatch() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(issue("issue-a", 1, "target-a"));
        confirm_current_for_test(&mut state);
        let old_binding_id = binding_id(&state);
        let old_fingerprint = state.worker_bindings["GET /api"]
            .agent_handle_fingerprint
            .clone();

        transfer_binding(
            &mut state,
            "replacement-runtime-handle",
            Some("replacement-worker".to_string()),
            "the prior runtime handle is unavailable after a new session".to_string(),
        )
        .unwrap();

        assert_ne!(binding_id(&state), old_binding_id);
        assert_eq!(
            dispatch_view(&state, None).state,
            RewriteWorkerDispatchState::Confirmed
        );
        let binding = &state.worker_bindings["GET /api"];
        assert_eq!(binding.transfer_generation, 1);
        assert_eq!(binding.agent_name.as_deref(), Some("replacement-worker"));
        let transfer = binding.last_transfer.as_ref().unwrap();
        assert_eq!(transfer.previous_agent_handle_fingerprint, old_fingerprint);
        assert!(transfer.reason.contains("prior runtime handle"));
    }

    #[test]
    fn transfer_rejects_a_handle_owned_by_another_api() {
        let mut state = implementation_state_with_inventory(true);
        confirm_current_for_test(&mut state);
        let other_fingerprint =
            fingerprint::id(&["rewrite-subagent-handle-v1", "other-api-runtime-handle"]);
        state.worker_bindings.insert(
            "POST /other".to_string(),
            RewriteWorkerBinding {
                agent_handle_fingerprint: other_fingerprint,
                agent_name: None,
                confirmed_dispatch_id: "other-dispatch".to_string(),
                transfer_generation: 0,
                last_transfer: None,
            },
        );

        let error = transfer_binding(
            &mut state,
            "other-api-runtime-handle",
            None,
            "replace unavailable owner".to_string(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("already bound to another API"));
    }

    #[test]
    fn transfer_entrypoint_requires_approval_and_current_binding_id() {
        let target = configured_target();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = implementation_state_with_inventory(false);
        confirm_current_for_test(&mut state);
        let current_binding_id = binding_id(&state);
        store.save(&state).unwrap();
        let options = |binding_id: &str, caller_approved| RewriteWorkerTransferOptions {
            target_root: target.path().to_path_buf(),
            binding_id: binding_id.to_string(),
            agent_handle: "replacement-runtime-handle".to_string(),
            agent_name: Some("replacement-worker".to_string()),
            reason: "stored handle is unavailable after session replacement".to_string(),
            caller_approved,
        };

        let error = transfer(options(&current_binding_id, false)).unwrap_err();
        assert!(error.to_string().contains("explicit caller approval"));
        assert_eq!(
            store.load().unwrap().unwrap().worker_bindings["GET /api"].transfer_generation,
            0
        );

        let error = transfer(options("stale-binding-id", true)).unwrap_err();
        assert!(error.to_string().contains("binding id is stale"));

        transfer(options(&current_binding_id, true)).unwrap();
        let persisted = store.load().unwrap().unwrap();
        assert_eq!(persisted.worker_bindings["GET /api"].transfer_generation, 1);
        assert!(current_is_confirmed(&persisted));
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

    #[test]
    fn confirmed_worker_advances_the_next_pending_api_before_waiting() {
        let mut state = implementation_state_with_inventory(true);
        confirm_current_for_test(&mut state);

        let action = serde_json::to_value(super::super::action::for_state(
            Path::new("/target"),
            &state,
        ))
        .unwrap();
        assert_eq!(action["action"]["kind"], "advance_required");
        assert_eq!(
            action.pointer("/action/commands/advance/argv"),
            Some(&serde_json::json!([
                "backend-rewrite",
                "--target-root",
                "/target",
                "next",
                "--api",
                "POST /other"
            ]))
        );
    }

    #[test]
    fn confirmed_worker_without_a_pending_api_remains_implementation_required() {
        let mut state = implementation_state_with_inventory(false);
        confirm_current_for_test(&mut state);

        let action = serde_json::to_value(super::super::action::for_state(
            Path::new("/target"),
            &state,
        ))
        .unwrap();
        assert_eq!(action["action"]["kind"], "implementation_required");
        assert_eq!(
            action.pointer("/action/details/worker/state"),
            Some(&serde_json::json!("confirmed"))
        );
        assert!(action.pointer("/action/commands/advance").is_none());
    }

    #[test]
    fn status_reconstructs_post_dispatch_pending_api_advance() {
        let target = committed_target();
        let mut state = implementation_state_with_inventory(true);
        confirm_current_for_test(&mut state);
        state.target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());

        let status =
            serde_json::to_value(super::super::action::for_status(target.path(), &state).unwrap())
                .unwrap();
        assert_eq!(status["action"]["kind"], "advance_required");
        assert_eq!(
            status.pointer("/action/commands/advance/argv/5"),
            Some(&serde_json::json!("POST /other"))
        );
    }

    fn implementation_state_with_inventory(include_pending: bool) -> RewriteState {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.active_issue = Some(issue("issue-a", 1, "target-a"));
        state.api_inventory = vec![api_progress("GET /api", RewriteApiStatus::Active)];
        if include_pending {
            state
                .api_inventory
                .push(api_progress("POST /other", RewriteApiStatus::Pending));
        }
        state.current_api_index = Some(0);
        state
    }

    fn api_progress(api: &str, status: RewriteApiStatus) -> RewriteApiProgress {
        RewriteApiProgress {
            api: api.to_string(),
            source_route: Some(api.split_once(' ').unwrap().1.to_string()),
            status,
            attempts: 0,
            e2e_current: false,
            comparison_current: false,
            verified_target_fingerprint: None,
        }
    }

    fn assert_confirmation_error(error: anyhow::Error, operation: &str) {
        let message = error.to_string();
        assert!(message.contains("API GET /api"), "{message}");
        assert!(message.contains(operation), "{message}");
        assert!(
            message.contains("action.commands.confirm_worker"),
            "{message}"
        );
    }

    fn configured_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
        crate::rewrite::test_support::install_project_config(
            target.path(),
            "master",
            crate::rewrite::test_support::managed_test_recorder(),
            None,
        );
        fs::write(
            target.path().join(".traffic-e2e/verification.yaml"),
            "version: 3\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        git_ok(target.path(), &["init", "-q", "-b", "master"]);
        git_ok(target.path(), &["config", "user.email", "test@example.com"]);
        git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        git_ok(target.path(), &["add", "."]);
        git_ok(target.path(), &["commit", "-q", "-m", "baseline"]);
        target
    }

    fn committed_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='target'\nversion='0.1.0'\n",
        )
        .unwrap();
        git_ok(target.path(), &["init"]);
        git_ok(target.path(), &["config", "user.email", "test@example.com"]);
        git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        git_ok(target.path(), &["add", "."]);
        git_ok(target.path(), &["commit", "-m", "baseline"]);
        target
    }

    fn git_ok(repository: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    }

    fn issue(id: &str, attempt: u64, target_fingerprint: &str) -> RewriteIssue {
        RewriteIssue {
            id: id.to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "implementation differs".to_string(),
            pointer_pattern: None,
            representative: None,
            response_diagnosis: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: target_fingerprint.to_string(),
            attempt,
            comparison_observation: None,
        }
    }
}
