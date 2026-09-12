use super::*;
use crate::rewrite::{self, model::RewritePhase, worker::tests::configured_target};
use std::{fs, process::Command};

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
        runtime_query: None,
    }
}

fn query() -> RewriteWorkerMissingQuery {
    RewriteWorkerMissingQuery {
        api_or_command: "ListAgents".into(),
        queried_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn snapshot(root: &Path) -> Vec<u8> {
    fs::read(crate::internal_runtime::root(root).join("rewrite/state.json")).unwrap()
}

#[test]
fn authorization_and_exact_base_branch_are_mandatory_without_mutation() {
    let target = fixture();
    let original = snapshot(target.path());
    let mut request = options(target.path());
    request.caller_approved = false;
    request.runtime_query = Some(query());
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
fn new_round_preserves_recording_scope_and_requires_review_before_workers() {
    let target = fixture();
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "only:\n  - GET /other\nrequire_comparison: false\n",
    )
    .unwrap();
    assert!(!allows_base_replay(target.path(), "master").unwrap());
    let report = begin(options(target.path())).unwrap();
    let saved = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_ne!(saved.workflow_id, report.previous_workflow_id);
    assert_eq!(saved.recording_run_id, "20260802000000");
    assert!(!saved.require_comparison);
    assert_eq!(saved.api, "GET /other");
    assert_eq!(saved.phase, RewritePhase::ApiPending);
    assert!(saved.active_issue.is_none());
    assert!(saved.delivery_review_required);
    assert!(
        saved
            .api_inventory
            .iter()
            .all(|a| a.attempts == 0 && !a.e2e_current)
    );
    let archived: RewriteState =
        serde_json::from_slice(&fs::read(report.archive).unwrap()).unwrap();
    assert_eq!(archived.workflow_id, report.previous_workflow_id);
    let value = serde_json::to_value(report.next).unwrap();
    assert_eq!(value["action"]["kind"], "source_review_required");
    assert_eq!(value["terminal_allowed"], false);
    assert!(allows_base_replay(target.path(), "master").unwrap());
    fs::write(
        target.path().join(".traffic-e2e/progress.yaml"),
        "version: 3\n",
    )
    .unwrap();
    git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
    git(target.path(), &["commit", "-qm", "publish progress"]);
    assert!(allows_base_replay(target.path(), "master").unwrap());
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    assert!(!allows_base_replay(target.path(), "master").unwrap());
    git(target.path(), &["add", "lib.rs"]);
    git(target.path(), &["commit", "-qm", "external update"]);
    assert!(!allows_base_replay(target.path(), "master").unwrap());
}

#[test]
fn previous_workers_need_actual_query_and_late_feedback_cannot_resurrect_them() {
    let target = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut previous = store.load().unwrap().unwrap();
    let scope = rewrite::RewriteWorkScope::Api {
        api: "GET /api".into(),
    };
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
    let original = snapshot(target.path());
    assert!(
        begin(options(target.path()))
            .unwrap_err()
            .to_string()
            .contains("stop all previous workers")
    );
    assert_eq!(snapshot(target.path()), original);
    let mut request = options(target.path());
    request.runtime_query = Some(query());
    let report = begin(request).unwrap();
    let archived: RewriteState =
        serde_json::from_slice(&fs::read(report.archive).unwrap()).unwrap();
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
fn active_coordinator_invalid_recording_and_bad_query_leave_old_round_intact() {
    let target = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let original = snapshot(target.path());
    {
        let _lock = store.lock().unwrap();
        assert!(begin(options(target.path())).is_err());
    }
    let mut request = options(target.path());
    request.runtime_query = Some(RewriteWorkerMissingQuery {
        api_or_command: "ListAgents".into(),
        queried_at: "yesterday".into(),
    });
    assert!(begin(request).unwrap_err().to_string().contains("RFC 3339"));
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
