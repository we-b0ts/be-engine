use super::*;
use crate::{self as rewrite, model::RewritePhase, worker::tests::configured_target};
use std::{fs, process::Command};

#[path = "review_tests.rs"]
mod review_tests;

#[path = "obsolete_state_tests.rs"]
mod obsolete_state_tests;

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
    crate::test_support::install_source_snapshot(target.path());
    let catalog = target
        .path()
        .join(".traffic-e2e/local/repository-analysis/catalog.json");
    fs::create_dir_all(catalog.parent().unwrap()).unwrap();
    fs::write(
        catalog,
        serde_json::to_vec(&serde_json::json!({
            "api_groups": {"/api": "api", "/other": "other"}
        }))
        .unwrap(),
    )
    .unwrap();
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
fn new_purpose_authorizes_first_batches_in_fixed_slots_for_each_api() {
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
        // Model completed group discovery with one fresh failure in each group.
        // Both purposes now use the real pool; no legacy per-API confirmation.
        let mut state = store.load().unwrap().unwrap();
        inventory::install(&mut state, vec!["GET /api".into(), "GET /other".into()]).unwrap();
        state.active_slice = worker::tests::implementation_state_with_inventory(false).active_slice;
        let mut other = state.active_slice.clone();
        other.api = "GET /other".into();
        other.source_route = "/other".into();
        state.parked_slices.insert(other.api.clone(), other);
        state.recording_run_id = "20260802000000".into();
        for item in &mut state.api_inventory {
            item.status = rewrite::RewriteApiStatus::ImplementationRequired;
            item.attempts = 1;
        }
        store.save(&state).unwrap();
        for (api, handle) in [("/api", "new-worker-a"), ("/other", "new-worker-b")] {
            let state = store.load().unwrap().unwrap();
            let Some(rewrite::RewriteAction::ImplementerDispatchRequired { dispatch, .. }) =
                crate::implementer::action(target.path(), &state).unwrap()
            else {
                panic!("a discovered failure must produce its fixed-slot batch");
            };
            assert_eq!(dispatch.apis.len(), 1);
            assert_eq!(dispatch.apis[0].api, api);
            fs::create_dir_all(dispatch.worktree.parent().unwrap()).unwrap();
            let branch = format!("implementer-slot-{}", dispatch.slot_id);
            git(
                target.path(),
                &[
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    &branch,
                    dispatch.worktree.to_str().unwrap(),
                    "HEAD",
                ],
            );
            let confirm = |agent: &str| {
                crate::implementer::confirm(rewrite::ImplementerConfirmOptions {
                    target_root: target.path().into(),
                    slot_id: dispatch.slot_id,
                    group_id: dispatch.group_id.clone(),
                    dispatch_id: dispatch.dispatch_id.clone(),
                    agent_handle: agent.into(),
                })
            };
            confirm(handle).unwrap();
            confirm(handle).unwrap(); // Idempotent confirmation does not grant another replacement.
            assert!(confirm("unapproved-replacement").is_err());
            let confirmed = store.load().unwrap().unwrap();
            assert_eq!(
                confirmed.implementers.as_ref().unwrap().slots[&dispatch.slot_id]
                    .agent_handle
                    .as_deref(),
                Some(handle)
            );
            assert_eq!(
                confirmed.worker_bindings[api].agent_handle.as_deref(),
                Some(handle)
            );
        }
        let confirmed = store.load().unwrap().unwrap();
        assert_eq!(confirmed.worker_bindings.len(), 2);
        assert_eq!(
            confirmed
                .implementers
                .as_ref()
                .unwrap()
                .effective_max_implementers,
            16
        );
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
        "only:\n  - /other\n",
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

#[tokio::test]
async fn replay_purpose_analyzes_case_patterns_and_groups_in_one_batch() {
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

    let catalog_path = target
        .path()
        .join(".traffic-e2e/local/repository-analysis/catalog.json");
    fs::write(
        &catalog_path,
        br#"{"api_groups":{"/api":"api","/api/known/*":"known"}}"#,
    )
    .unwrap();
    let run = artifacts::recording_run(target.path(), &previous.recording_run_id);
    for (index, path) in [
        "/api/knowledge-bases/304487/artifacts",
        "/api/knowledge-bases/304541/artifacts",
        "/api/known/1",
        "/new-static",
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
            "published_cases":6
        }))
        .unwrap(),
    )
    .unwrap();

    let report = begin(options(target.path())).unwrap();
    let rewrite::RewriteAction::RepositoryAnalysisRequired { analysis, .. } = report.next.action
    else {
        panic!("expected one combined analysis action");
    };
    assert_eq!(analysis.pending_apis, ["/other"]);
    assert_eq!(
        analysis.case_patterns.unwrap().candidates,
        [
            "GET /api/knowledge-bases/304487/artifacts",
            "GET /api/knowledge-bases/304541/artifacts",
            "GET /api/known/1",
            "GET /new-static",
        ]
    );
    assert!(store.load().unwrap().unwrap().api_inventory.is_empty());

    let file = target
        .path()
        .join(".traffic-e2e/local/new-api-analysis.json");
    let request = rewrite::RepositoryAnalysisApplyOptions {
        target_root: target.path().into(),
        batch_id: analysis.batch_id,
        file: file.clone(),
    };
    let policy = target.path().join(".traffic-e2e/policy.yaml");
    let before_policy = fs::read(&policy).unwrap();
    let before_catalog = fs::read(&catalog_path).unwrap();
    let valid = serde_json::json!({
        "schema_version": 1,
        "catalog_revision": analysis.catalog_revision,
        "case_patterns": {
            "GET /api/knowledge-bases/304487/artifacts": "/api/knowledge-bases/*/artifacts",
            "GET /api/knowledge-bases/304541/artifacts": "/api/knowledge-bases/*/artifacts",
            "GET /api/known/1": "/api/known/*",
            "GET /new-static": null,
        },
        "assignments": {
            "/api/knowledge-bases/*/artifacts": "knowledge-artifacts",
            "/new-static": "static",
            "/other": "other",
        }
    });

    for field in ["case_patterns", "assignments"] {
        let mut invalid = valid.clone();
        let entries = invalid[field].as_object_mut().unwrap();
        let first = entries.keys().next().unwrap().clone();
        entries.remove(&first);
        fs::write(&file, invalid.to_string()).unwrap();
        assert!(rewrite::apply_repository_analysis(request.clone()).is_err());
        assert_eq!(fs::read(&policy).unwrap(), before_policy);
        assert_eq!(fs::read(&catalog_path).unwrap(), before_catalog);
    }

    fs::write(&file, valid.to_string()).unwrap();
    let outcome = rewrite::apply_repository_analysis(request.clone()).unwrap();
    assert!(matches!(
        outcome.action,
        crate::RewriteAction::AdvanceRequired { .. }
    ));
    let state = store.load().unwrap().unwrap();
    assert!(state.case_pattern_identification.is_none());
    assert!(state.api_catalog.contains("GET /new-static"));
    let revision = state.revision;
    crate::apply_repository_analysis(request).unwrap();
    assert_eq!(store.load().unwrap().unwrap().revision, revision);

    git(target.path(), &["add", ".traffic-e2e/policy.yaml"]);
    git(target.path(), &["commit", "-qm", "apply case paths"]);
    let next = rewrite::advance::advance_rewrite(rewrite::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert!(!matches!(
        next.envelope.action,
        crate::RewriteAction::RepositoryAnalysisRequired { .. }
    ));
    let state = store.load().unwrap().unwrap();
    assert!(rewrite::repository_analysis::is_complete(&state));
    assert!(state.api_inventory.iter().all(|item| item.attempts == 0));
    assert_eq!(
        state.repository_analysis.unwrap().api_groups,
        [
            ("/api", "api"),
            ("/api/knowledge-bases/*/artifacts", "knowledge-artifacts"),
            ("/api/known/*", "known"),
            ("/new-static", "static"),
            ("/other", "other"),
        ]
        .into_iter()
        .map(|(api, group)| (api.to_owned(), group.to_owned()))
        .collect()
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
            delivery_commit: None,
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
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        report.action,
        crate::RewriteAction::PurposeRequired { .. }
    ));
    let report = rewrite::wait_rewrite(rewrite::RewriteWaitOptions {
        target_root: target.path().into(),
        seconds: 1,
    })
    .await
    .unwrap();
    assert!(matches!(
        report.action,
        crate::RewriteAction::PurposeRequired { .. }
    ));
    assert_eq!(snapshot(target.path()), original);
}

#[test]
fn fresh_recording_supersedes_old_pin_without_needing_usable_old_evidence() {
    let target = fixture();
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "recording_run_id: '20260101000000'\n",
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
    crate::recording_input::bind(target.path(), &mut adopted, None).unwrap();
    store.save(&adopted).unwrap();
    let status = rewrite::status_rewrite(rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        crate::RewriteAction::AdvanceRequired { .. }
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
        crate::RewriteAction::AdvanceRequired { .. }
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
        crate::RewriteAction::InputRequired {
            reason: crate::RewriteInputRequiredReason::RecordingEvidenceRequired,
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
        crate::purpose::base_branch(target.path()).unwrap(),
        Some("master".into())
    );
    assert!(rewrite::purpose::pending(target.path()).unwrap().is_some());
}
