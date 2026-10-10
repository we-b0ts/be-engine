use super::*;
use crate::rewrite::{self, model::RewritePhase, worker::tests::configured_target};
use std::{fs, process::Command};

#[path = "review_tests.rs"]
mod review_tests;

fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}

fn fixture() -> tempfile::TempDir {
    let target = configured_target();
    git(target.path(), &["switch", "-q", "master"]);
    fs::write(
        target.path().join(".gitignore"),
        "/.traffic-e2e/local/\n/.traffic-e2e/regression.yaml\n",
    )
    .unwrap();
    git(target.path(), &["add", ".gitignore"]);
    git(target.path(), &["commit", "-qm", "ignore runtime"]);
    let mut state = rewrite::worker::tests::implementation_state_with_inventory(false);
    state.recording_apis = vec!["GET /api".into(), "GET /other".into()];
    let issue = state.active_issue.clone();
    let apis = state.recording_apis.clone();
    inventory::install(&mut state, apis).unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = issue;
    let run = artifacts::recording_run(target.path(), &state.recording_run_id);
    for (index, path) in ["/api", "/other"].iter().enumerate() {
        let case = run.join("apis/cases").join(format!("case-{index}"));
        fs::create_dir_all(&case).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::to_vec(&serde_json::json!({"method":"GET", "uri":path})).unwrap(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}\n").unwrap();
    }
    fs::write(run.join("recording-run.json"), serde_json::to_vec(&serde_json::json!({"status":"completed", "recording_apis":state.recording_apis, "published_cases":2})).unwrap()).unwrap();
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    target
}

fn options(root: &Path) -> RewriteRegressionBeginOptions {
    RewriteRegressionBeginOptions {
        target_root: root.into(),
        caller_approved: true,
        record_new_traffic: false,
        active_agent_count: 0,
        runtime_query: rewrite::RewriteWorkerMissingQuery {
            api_or_command: "test_runtime.list_current_session_agents".into(),
            queried_at: chrono::Utc::now().to_rfc3339(),
        },
    }
}

fn snapshot(root: &Path) -> Vec<u8> {
    fs::read(crate::internal_runtime::root(root).join("rewrite/state.json")).unwrap()
}

#[test]
fn current_session_query_must_report_zero_for_both_purposes_before_mutation() {
    let target = fixture();
    let original = snapshot(target.path());
    let branches = source_diff::git_text(target.path(), &["show-ref"]).unwrap();
    for record_new_traffic in [false, true] {
        for (count, command, time) in [
            (1, "ListAgents", "2026-09-12T09:00:00Z"),
            (0, "", "2026-09-12T09:00:00Z"),
            (0, "ListAgents", "unknown"),
        ] {
            let result = begin(RewriteRegressionBeginOptions {
                record_new_traffic,
                active_agent_count: count,
                runtime_query: rewrite::RewriteWorkerMissingQuery {
                    api_or_command: command.into(),
                    queried_at: time.into(),
                },
                ..options(target.path())
            });
            assert!(result.is_err());
            assert_eq!(snapshot(target.path()), original);
            assert_eq!(
                source_diff::git_text(target.path(), &["show-ref"]).unwrap(),
                branches
            );
        }
    }
}

#[test]
fn new_purpose_authorizes_one_first_binding_independently_for_each_api() {
    for record_new_traffic in [false, true] {
        let target = fixture();
        let store = RewriteStore::new(target.path()).unwrap();
        let query = options(target.path()).runtime_query;
        begin(RewriteRegressionBeginOptions {
            record_new_traffic,
            runtime_query: query.clone(),
            ..options(target.path())
        })
        .unwrap();
        let state = store.load().unwrap().unwrap();
        let origin = state.regression.as_ref().unwrap();
        assert_eq!(origin.active_session_agent_count, Some(0));
        assert_eq!(
            origin
                .session_runtime_query
                .as_ref()
                .unwrap()
                .api_or_command,
            query.api_or_command
        );
        assert_eq!(
            origin.session_runtime_query.as_ref().unwrap().queried_at,
            query.queried_at
        );
        for (api, handle) in [("GET /api", "new-worker-a"), ("GET /other", "new-worker-b")] {
            // Model a fresh Replay failure for each API in the new workflow.
            let mut state = store.load().unwrap().unwrap();
            if !state.api_inventory.iter().any(|item| item.api == api) {
                let mut item = worker::tests::implementation_state_with_inventory(false)
                    .api_inventory[0]
                    .clone();
                item.api = api.into();
                item.status = rewrite::RewriteApiStatus::ImplementationRequired;
                state.api_inventory.push(item);
            }
            state.active_slice =
                worker::tests::implementation_state_with_inventory(false).active_slice;
            state.api = api.into();
            let index = state
                .api_inventory
                .iter()
                .position(|item| item.api == api)
                .unwrap();
            state.api_inventory[index].status = rewrite::RewriteApiStatus::ImplementationRequired;
            state.current_api_index = Some(index);
            store.save(&state).unwrap();
            let confirm = |agent: &str| {
                worker::confirm(rewrite::RewriteWorkerConfirmOptions {
                    target_root: target.path().into(),
                    work_scope: rewrite::RewriteWorkScope::Api {
                        api: rewrite::api_selector::public_api(api).into(),
                    },
                    worktree: None,
                    agent_handle: agent.into(),
                    agent_name: None,
                })
            };
            confirm(handle).unwrap();
            confirm(handle).unwrap(); // Idempotent confirmation does not grant another replacement.
            assert!(
                confirm("unapproved-replacement")
                    .unwrap_err()
                    .to_string()
                    .contains("ownership transfer")
            );
        }
        assert_eq!(store.load().unwrap().unwrap().worker_bindings.len(), 2);
    }
}

#[test]
fn authorization_and_exact_base_branch_are_mandatory_without_mutation() {
    let target = fixture();
    let original = snapshot(target.path());
    let mut request = options(target.path());
    request.caller_approved = false;
    assert!(
        begin(request)
            .unwrap_err()
            .to_string()
            .contains("explicit user authorization")
    );
    git(target.path(), &["switch", "-qc", "feature-same-commit"]);
    assert!(
        begin(options(target.path()))
            .unwrap_err()
            .to_string()
            .contains("equal commits")
    );
    git(target.path(), &["checkout", "-q", "--detach"]);
    assert!(format!("{:#}", begin(options(target.path())).unwrap_err()).contains("detached HEAD"));
    assert_eq!(snapshot(target.path()), original);
}

#[test]
fn new_round_preserves_recording_scope_and_replays_before_workers() {
    let target = fixture();
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "only:\n  - /other\nrequire_comparison: false\n",
    )
    .unwrap();
    let report = begin(options(target.path())).unwrap();
    let saved = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_ne!(
        saved.workflow_id,
        report.previous_workflow_id.clone().unwrap()
    );
    assert_eq!(saved.recording_run_id, "20260802000000");
    assert!(!saved.require_comparison);
    assert_eq!(saved.api, "GET /other");
    assert_eq!(saved.phase, RewritePhase::ApiPending);
    assert!(saved.active_issue.is_none());
    assert!(!saved.delivery_review_required);
    assert!(
        saved
            .api_inventory
            .iter()
            .all(|a| a.attempts == 0 && !a.e2e_current)
    );
    let archived: RewriteState =
        serde_json::from_slice(&fs::read(report.archive.unwrap()).unwrap()).unwrap();
    assert_eq!(
        archived.workflow_id,
        report.previous_workflow_id.clone().unwrap()
    );
    let value = serde_json::to_value(report.next).unwrap();
    assert_eq!(value["action"]["kind"], "advance_required");
    assert_eq!(value["terminal_allowed"], false);
    assert!(
        super::super::purpose::pending(target.path())
            .unwrap()
            .is_none()
    );
    git(target.path(), &["switch", "-q", "master"]);
    assert!(
        super::super::purpose::pending(target.path())
            .unwrap()
            .is_some()
    );
}

#[test]
fn replay_purpose_identifies_uncovered_patterns_before_installing_inventory() {
    let target = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut previous = store.load().unwrap().unwrap();
    previous.recording_apis.clear();
    previous.api_catalog_initialized = true;
    previous.api_catalog = ["GET /api", "GET /other"]
        .into_iter()
        .map(str::to_string)
        .collect();
    store.save(&previous).unwrap();

    let run = artifacts::recording_run(target.path(), &previous.recording_run_id);
    for (index, path) in [
        "/api/knowledge-bases/304487/artifacts",
        "/api/knowledge-bases/304541/artifacts",
    ]
    .iter()
    .enumerate()
    {
        let case = run.join("apis/cases").join(format!("new-case-{index}"));
        fs::create_dir_all(&case).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::to_vec(&serde_json::json!({"method":"GET", "uri":path})).unwrap(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}\n").unwrap();
    }
    fs::write(
        run.join("recording-run.json"),
        serde_json::to_vec(&serde_json::json!({
            "status":"completed",
            "recording_apis":[],
            "published_cases":4
        }))
        .unwrap(),
    )
    .unwrap();

    let report = begin(options(target.path())).unwrap();
    let value = serde_json::to_value(&report.next).unwrap();
    assert_eq!(
        value["action"]["kind"],
        "case_pattern_identification_required"
    );
    assert_eq!(
        value["action"]["details"]["candidates"],
        serde_json::json!([
            "GET /api/knowledge-bases/304487/artifacts",
            "GET /api/knowledge-bases/304541/artifacts"
        ])
    );

    let pending = store
        .load()
        .unwrap()
        .unwrap()
        .case_pattern_identification
        .unwrap();
    assert!(store.load().unwrap().unwrap().api_inventory.is_empty());
    case_patterns::apply(case_patterns::RewriteCasePatternApplyOptions {
        target_root: target.path().into(),
        batch_id: pending.id,
        patterns: vec!["/api/knowledge-bases/*/artifacts".into()],
    })
    .unwrap();

    let state = store.load().unwrap().unwrap();
    assert_eq!(
        artifacts::standard_recording_apis(target.path(), &state).unwrap(),
        [
            "GET /api",
            "GET /api/knowledge-bases/*/artifacts",
            "GET /other"
        ]
    );
}

#[test]
fn previous_workers_are_retired_without_query_and_late_feedback_is_rejected() {
    let target = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut previous = store.load().unwrap().unwrap();
    let scope = rewrite::RewriteWorkScope::Api { api: "/api".into() };
    let binding: worker::model::RewriteWorkerBinding = serde_json::from_value(serde_json::json!({
        "agent_handle":"old-worker", "agent_handle_fingerprint":"old-fingerprint", "confirmed_dispatch_id":"old-dispatch",
        "first_bound_at":"2020-01-01T00:00:00Z",
        "expert": {"id":"old-expert-id", "apis":["GET /api"], "prepared_at":"2020-01-01T03:00:00Z", "agent_handle":"old-expert", "agent_handle_fingerprint":"expert-fingerprint", "confirmed_at":"2020-01-01T03:00:00Z"}
    })).unwrap();
    previous
        .worker_bindings
        .insert(scope.binding_key(), binding);
    {
        let _feedback = worker::events::lock(target.path()).unwrap();
        worker::events::publish(target.path(), &previous, &scope).unwrap();
    }
    let report = begin(options(target.path())).unwrap();
    let archived: RewriteState =
        serde_json::from_slice(&fs::read(report.archive.unwrap()).unwrap()).unwrap();
    assert!(archived.worker_bindings.contains_key(&scope.binding_key()));
    assert!(store.load().unwrap().unwrap().worker_bindings.is_empty());
    assert!(
        worker::runtime::report(rewrite::RewriteWorkerReportOptions {
            target_root: target.path().into(),
            agent_handle: "old-worker".into(),
            activity: rewrite::RewriteWorkerActivity::Running,
            handoff_id: None,
            review_report: None,
        })
        .is_err()
    );
    assert!(store.load().unwrap().unwrap().worker_bindings.is_empty());
}

#[test]
fn active_coordinator_and_invalid_recording_leave_old_round_intact() {
    let target = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let original = snapshot(target.path());
    {
        let _lock = store.lock().unwrap();
        assert!(begin(options(target.path())).is_err());
    }
    fs::write(
        artifacts::recording_run(target.path(), "20260802000000").join("recording-run.json"),
        "{\"status\":\"running\"}",
    )
    .unwrap();
    assert!(begin(options(target.path())).is_err());
    assert_eq!(snapshot(target.path()), original);
}

#[test]
fn archive_failure_does_not_replace_current_state() {
    let target = fixture();
    let original = snapshot(target.path());
    fs::write(
        crate::internal_runtime::root(target.path()).join("rewrite/history"),
        "blocked",
    )
    .unwrap();
    assert!(begin(options(target.path())).is_err());
    assert_eq!(snapshot(target.path()), original);
}

#[test]
fn live_and_stale_traffic_leases_cannot_be_reset() {
    let target = fixture();
    let original = snapshot(target.path());
    for pid in [std::process::id(), u32::MAX] {
        let claim = traffic_operation::claim(
            target.path(),
            traffic_operation::TrafficOperationMarker {
                operation_id: "old-replay".into(),
                kind: traffic_operation::TrafficOperationKind::Replay,
                api: Some("GET /api".into()),
                started_at: chrono::Utc::now().to_rfc3339(),
                pid,
            },
        )
        .unwrap();
        assert!(matches!(
            claim,
            traffic_operation::TrafficOperationClaim::Acquired(_)
        ));
        assert!(
            begin(options(target.path()))
                .unwrap_err()
                .to_string()
                .contains("previous traffic operation")
        );
        assert_eq!(snapshot(target.path()), original);
        drop(claim);
    }
}

#[test]
fn completed_failure_marker_is_retired_but_unfinished_operation_blocks_begin() {
    let target = fixture();
    let directory = crate::internal_runtime::root(target.path()).join("rewrite/operations");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("current.json");
    let original = snapshot(target.path());
    let mut marker = serde_json::json!({"id":"old-operation", "pid":u32::MAX,
        "request":{"kind":"next", "api":"GET /api"}, "finished":false});
    fs::write(&path, serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(begin(options(target.path())).is_err());
    assert_eq!(snapshot(target.path()), original);
    marker["finished"] = true.into();
    marker["error"] = "old operation failed".into();
    fs::write(&path, serde_json::to_vec(&marker).unwrap()).unwrap();
    begin(options(target.path())).unwrap();
    assert!(!path.exists());
    assert!(execution::status_action(target.path()).unwrap().is_none());
}

#[tokio::test]
async fn every_base_status_requires_purpose_and_next_wait_cannot_resume_old_work() {
    let target = fixture();
    let original = snapshot(target.path());
    for _ in 0..2 {
        let report = rewrite::status_rewrite(rewrite::RewriteContext {
            target_root: target.path().into(),
        })
        .unwrap();
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["action"]["kind"], "purpose_required");
        assert_eq!(json["terminal_allowed"], false);
        assert!(
            json["action"]["commands"]["record"]["argv"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("record"))
        );
    }
    let report = rewrite::next_rewrite(rewrite::RewriteNextOptions {
        target_root: target.path().into(),
        api: Some("/api".parse().unwrap()),
        process_output: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        report.action,
        rewrite::RewriteAction::PurposeRequired { .. }
    ));
    let report = rewrite::wait_rewrite(rewrite::RewriteWaitOptions {
        target_root: target.path().into(),
        seconds: 1,
    })
    .await
    .unwrap();
    assert!(matches!(
        report.action,
        rewrite::RewriteAction::PurposeRequired { .. }
    ));
    assert_eq!(snapshot(target.path()), original);
}

#[test]
fn fresh_recording_supersedes_old_pin_without_needing_usable_old_evidence() {
    let target = fixture();
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "recording_run_id: '20260101000000'\nrequire_comparison: false\n",
    )
    .unwrap();
    let mut request = options(target.path());
    request.record_new_traffic = true;
    let report = begin(request).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.phase, RewritePhase::RecordingRequired);
    assert_ne!(state.recording_run_id, "20260101000000");
    assert_ne!(state.recording_run_id, "20260802000000");
    assert!(state.worker_bindings.is_empty());
    assert!(state.active_issue.is_none());
    assert!(state.recording_input_case_source.is_none());
    assert_eq!(
        state.recording_request_reason,
        Some(rewrite::RewriteRecordingReason::UserRequested)
    );
    assert_eq!(
        serde_json::to_value(report.next).unwrap()["action"]["kind"],
        "input_required"
    );
    assert!(rewrite::purpose::pending(target.path()).unwrap().is_none());
    // A published new recording advances towards Replay instead of the stale worker issue.
    assert!(state.recording_run_id.is_empty());
    let external_run_id = "20261010000000";
    let run = artifacts::recording_run(target.path(), external_run_id);
    for (index, uri) in ["/api", "/other"].iter().enumerate() {
        let case = run.join("apis/cases").join(format!("case-{index}"));
        fs::create_dir_all(&case).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::to_vec(&serde_json::json!({"method":"GET","uri":uri})).unwrap(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();
    }
    fs::write(run.join("recording-run.json"), serde_json::to_vec(&serde_json::json!({"status":"completed","recording_apis":state.recording_apis,"published_cases":2})).unwrap()).unwrap();
    let mut adopted = store.load().unwrap().unwrap();
    assert!(!regression_scope::has_active_pin(target.path(), &adopted).unwrap());
    rewrite::recording_input::bind(target.path(), &mut adopted, None).unwrap();
    store.save(&adopted).unwrap();
    let status = rewrite::status_rewrite(rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        rewrite::RewriteAction::AdvanceRequired { .. }
    ));
    assert_eq!(
        store.load().unwrap().unwrap().recording_run_id,
        external_run_id
    );
    git(target.path(), &["switch", "-q", "master"]);
    let report = begin(RewriteRegressionBeginOptions {
        ..options(target.path())
    })
    .unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().recording_run_id,
        external_run_id
    );
    assert!(matches!(
        report.next.action,
        rewrite::RewriteAction::AdvanceRequired { .. }
    ));
}

#[test]
fn purpose_is_required_without_workflow_and_new_traffic_can_initialize_it() {
    let target = configured_target();
    git(target.path(), &["switch", "-q", "master"]);
    assert!(rewrite::purpose::pending(target.path()).unwrap().is_some());
    let report = begin(RewriteRegressionBeginOptions {
        record_new_traffic: true,
        ..options(target.path())
    })
    .unwrap();
    assert!(report.archive.is_none());
    assert!(report.previous_workflow_id.is_none());
    assert!(matches!(
        report.next.action,
        rewrite::RewriteAction::InputRequired {
            reason: crate::rewrite::RewriteInputRequiredReason::RecordingEvidenceRequired,
            ..
        }
    ));
}

#[test]
fn confirmation_creates_unique_branches_and_returning_to_base_always_requires_purpose() {
    let target = fixture();
    let first = begin(options(target.path())).unwrap();
    let first_branch = source_diff::git_text(target.path(), &["branch", "--show-current"]).unwrap();
    assert_eq!(first_branch.trim(), first.work_branch);
    git(target.path(), &["switch", "-q", "master"]);
    assert!(rewrite::purpose::pending(target.path()).unwrap().is_some());
    let second = begin(options(target.path())).unwrap();
    assert_ne!(first.work_branch, second.work_branch);
    assert!(second.work_branch.starts_with("replay/"));
    assert!(first.work_branch.ends_with("-1"));
    assert!(second.work_branch.ends_with("-2"));
    assert_eq!(
        source_diff::git_text(target.path(), &["branch", "--show-current"])
            .unwrap()
            .trim(),
        second.work_branch
    );
}

#[test]
fn failed_branch_creation_restores_old_state_without_dispatching_it() {
    let target = fixture();
    let original = snapshot(target.path());
    fs::write(target.path().join(".git/HEAD.lock"), "blocked checkout").unwrap();
    assert!(begin(options(target.path())).is_err());
    assert_eq!(snapshot(target.path()), original);
    assert_eq!(
        rewrite::purpose::base_branch(target.path()).unwrap(),
        Some("master".into())
    );
    assert!(rewrite::purpose::pending(target.path()).unwrap().is_some());
}
