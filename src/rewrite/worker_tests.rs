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

fn api_scope(state: &RewriteState) -> RewriteWorkScope {
    RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    }
}

fn dispatch_view(state: &RewriteState, requested_api: Option<String>) -> RewriteWorkerDispatchView {
    super::dispatch_view(
        state,
        api_scope(state),
        requested_api.map(|api| RewriteWorkScope::Api { api }),
    )
}

fn gate_envelope(
    target_root: &Path,
    state: &RewriteState,
    requested_api: Option<String>,
) -> RewriteActionEnvelope {
    super::gate_envelope(
        target_root,
        state,
        requested_api.map(|api| RewriteWorkScope::Api { api }),
    )
}

fn confirm_binding(
    state: &mut RewriteState,
    expected_dispatch_id: &str,
    agent_handle: &str,
    agent_name: Option<String>,
) -> Result<bool> {
    let scope = api_scope(state);
    super::confirm_binding(
        state,
        &scope,
        expected_dispatch_id,
        agent_handle,
        agent_name,
    )
}

fn transfer_binding(
    state: &mut RewriteState,
    agent_handle: &str,
    agent_name: Option<String>,
    reason: String,
) -> Result<()> {
    let scope = api_scope(state);
    super::transfer_binding(
        state,
        &scope,
        agent_handle,
        agent_name,
        reason,
        RewriteWorkerTransferAuthorization::UserApproved,
    )
}

fn binding_id(state: &RewriteState) -> String {
    super::binding_id(state, &api_scope(state))
}

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
                response_jwts: Vec::new(),
                header_dates: Vec::new(),
                dynamic_value: None,
                mysql_time: None,
                redis_time: None,
                dependency_request: None,
                time: None,
                jwt: None,
                evidence_id: evidence_id.clone(),
                body_codec: crate::ResponseBodyCodec::Json,
                kind: Some(ResponseRuleKind::Uuid),
                json_pointer: Some("/request_id".to_string()),
                source_evidence: Some("src/id.rs:new".to_string()),
                source_example: None,
                target_example: None,
                separator: None,
                unordered_paths: Vec::new(),
                unordered_joined_string_paths: Vec::new(),
                docx_timestamps: Vec::new(),
            },
        )
        .unwrap_err(),
        "planning a verification rule",
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
            cause: RewriteRouteCause::ReplayCapabilityGap {
                required_change: "support the replay contract".to_string(),
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
        serde_json::to_string(&dispatch_view(&state, None))
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
    let old_fingerprint = state.worker_bindings["/api"]
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
    let binding = &state.worker_bindings["/api"];
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
        "/other".to_string(),
        RewriteWorkerBinding {
            review_assignment: None,
            review_report: None,
            agent_handle_fingerprint: other_fingerprint,
            agent_handle: Some("other-api-runtime-handle".into()),
            agent_name: None,
            confirmed_dispatch_id: "other-dispatch".to_string(),
            first_bound_at: None,
            last_integrated_at: None,
            last_integrated_commit: None,
            expert: None,
            transfer_generation: 0,
            rework_generation: 0,
            last_transfer: None,
            observation: None,
        },
    );

    let error = transfer_binding(
        &mut state,
        "other-api-runtime-handle",
        None,
        "replace unavailable owner".to_string(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("already bound to another work item")
    );
}

#[test]
fn transfer_entrypoint_requires_approval_and_current_handle() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = implementation_state_with_inventory(false);
    confirm_current_for_test(&mut state);
    let current_handle = state.worker_bindings["/api"].agent_handle.clone().unwrap();
    store.save(&state).unwrap();
    let options = |previous_handle: &str, caller_approved| RewriteWorkerTransferOptions {
        target_root: target.path().to_path_buf(),
        previous_agent_handle: previous_handle.to_string(),
        agent_handle: "replacement-runtime-handle".to_string(),
        agent_name: Some("replacement-worker".to_string()),
        reason: "stored handle is unavailable after session replacement".to_string(),
        caller_approved,
        runtime_query: None,
    };

    let error = transfer(options(&current_handle, false)).unwrap_err();
    assert!(error.to_string().contains("explicit user approval"));
    assert_eq!(
        store.load().unwrap().unwrap().worker_bindings["/api"].transfer_generation,
        0
    );

    let error = transfer(options("stale-handle", true)).unwrap_err();
    assert!(error.to_string().contains("no outstanding worker binding"));

    transfer(options(&current_handle, true)).unwrap();
    let persisted = store.load().unwrap().unwrap();
    assert_eq!(persisted.worker_bindings["/api"].transfer_generation, 1);
    assert!(current_is_confirmed(&persisted));
}

#[test]
fn work_item_diagnostics_retain_a_structured_dispatch_gate() {
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
    assert!(
        blocked["action"]["commands"]["confirm_worker"]["required_env_names"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(AGENT_HANDLE_ENV))
    );

    confirm_current_for_test(&mut state);
    let confirmed = serde_json::to_value(action::for_state(target, &state)).unwrap();
    assert_eq!(confirmed["action"]["kind"], "wait_required");
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
            "next"
        ]))
    );
}

#[test]
fn confirmed_running_worker_without_executable_work_waits_for_handoff() {
    let mut state = implementation_state_with_inventory(false);
    confirm_current_for_test(&mut state);

    let action = serde_json::to_value(super::super::action::for_state(
        Path::new("/target"),
        &state,
    ))
    .unwrap();
    assert_eq!(action["action"]["kind"], "wait_required");
    assert_eq!(action["pending"], 1);
    assert!(action.pointer("/action/commands/advance").is_none());
}

#[test]
fn status_reconstructs_post_dispatch_pending_api_advance() {
    let target = committed_target();
    let mut state = implementation_state_with_inventory(true);
    confirm_current_for_test(&mut state);
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(target.path()).unwrap());

    let status =
        serde_json::to_value(super::super::action::for_status(target.path(), &state).unwrap())
            .unwrap();
    assert_eq!(status["action"]["kind"], "advance_required");
    assert_eq!(
        status.pointer("/action/details/api"),
        Some(&serde_json::json!("/other"))
    );
}

#[test]
fn status_recovers_confirmation_and_advance_across_repeated_worker_dispatches() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = implementation_state_with_inventory(true);
    state.target_fingerprint = Some(fingerprint::repository_fingerprint(target.path()).unwrap());
    store.save(&state).unwrap();
    let status = || {
        serde_json::to_value(
            super::super::status_rewrite(RewriteContext {
                target_root: target.path().to_path_buf(),
            })
            .unwrap(),
        )
        .unwrap()
    };
    let confirm_dispatch = || {
        confirm(RewriteWorkerConfirmOptions {
            worktree: Some(target.path().to_path_buf()),
            target_root: target.path().to_path_buf(),
            work_scope: RewriteWorkScope::Api { api: "/api".into() },
            agent_handle: "persistent-worker".into(),
            agent_name: None,
        })?;
        runtime::report(runtime::RewriteWorkerReportOptions {
            review_report: None,
            target_root: target.path().to_path_buf(),
            agent_handle: "persistent-worker".into(),
            activity: model::RewriteWorkerActivity::Running,
            handoff_id: None,
        })
    };

    let initial = status();
    assert_eq!(initial["action"]["kind"], "implementation_required");
    assert!(
        initial["action"]["summary"]
            .as_str()
            .unwrap()
            .starts_with("dispatch the dedicated subagent")
    );
    assert!(
        initial["action"]["summary"]
            .as_str()
            .unwrap()
            .contains("commands.confirm_worker")
    );
    assert_eq!(
        initial["action"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["commands", "details", "kind", "summary"]
    );
    let first_dispatch = initial["action"]["details"]["worker"]["dispatch_id"].clone();
    let confirmed = serde_json::to_value(confirm_dispatch().unwrap()).unwrap();
    assert_eq!(confirmed["action"]["kind"], "advance_required");

    // A later failed acceptance keeps the worker and creates a new dispatch.
    let mut state = store.load().unwrap().unwrap();
    let binding = binding_id(&state);
    state.active_issue = Some(issue("issue-later", 2, "target-b"));
    state.bump();
    store.save(&state).unwrap();
    let resumed = status();
    assert_eq!(
        resumed["action"]["details"]["worker"]["state"],
        "resume_required"
    );
    assert_eq!(
        resumed["action"]["details"]["worker"]["binding_id"],
        binding
    );
    assert!(
        resumed["action"]["summary"]
            .as_str()
            .unwrap()
            .starts_with("resume the bound subagent")
    );
    assert!(
        resumed["action"]["summary"]
            .as_str()
            .unwrap()
            .contains("commands.confirm_worker")
    );
    let next_dispatch = resumed["action"]["details"]["worker"]["dispatch_id"].clone();
    assert_ne!(first_dispatch, next_dispatch);
    let confirmed = serde_json::to_value(confirm_dispatch().unwrap()).unwrap();

    // If that response is lost during side work, status restores its command.
    let persisted = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let recovered = status();
    assert_eq!(confirmed["action"]["kind"], "advance_required");
    assert_eq!(recovered["action"], confirmed["action"]);
    assert_eq!(
        recovered["action"]["commands"]["advance"]["argv"],
        serde_json::json!(["backend-rewrite", "--target-root", target.path(), "next"])
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        persisted
    );
}

pub(in crate::rewrite) fn implementation_state_with_inventory(
    include_pending: bool,
) -> RewriteState {
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
        verified_target_fingerprint: None,
    }
}

fn assert_confirmation_error(error: anyhow::Error, operation: &str) {
    let message = error.to_string();
    assert!(message.contains("API /api"), "{message}");
    assert!(message.contains(operation), "{message}");
    assert!(
        message.contains("action.commands.confirm_worker"),
        "{message}"
    );
}

pub(in crate::rewrite) fn configured_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        None,
    );
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    git_ok(target.path(), &["init", "-q", "-b", "master"]);
    git_ok(target.path(), &["config", "user.email", "test@example.com"]);
    git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
    git_ok(target.path(), &["add", "."]);
    git_ok(target.path(), &["commit", "-q", "-m", "baseline"]);
    git_ok(target.path(), &["switch", "-q", "-c", "feature"]);
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

pub(in crate::rewrite) fn issue(id: &str, attempt: u64, target_fingerprint: &str) -> RewriteIssue {
    RewriteIssue {
        id: id.to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "implementation differs".to_string(),
        pointer_pattern: None,
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: target_fingerprint.to_string(),
        attempt,
    }
}
use crate::rewrite::evidence;
