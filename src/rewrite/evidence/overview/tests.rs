use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::json;

use super::*;
use crate::rewrite::model::{
    RewriteAttemptDelta, RewriteIssueKind, RewriteIssueOwner, RewritePhase,
};
use crate::rewrite::process_output_model::{
    RewriteProcessOutputProgress, RewriteProcessOutputStatus,
};
use crate::rewrite::store::RewriteStore;
use crate::rewrite::{
    RewriteContext, action, inventory, query_rewrite_evidence, query_rewrite_evidence_for_scope,
    status_rewrite_for_api,
};

fn issue(id: &str) -> RewriteIssue {
    RewriteIssue {
        id: id.to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "two responses returned HTTP 500 instead of 200".to_string(),
        pointer_pattern: Some("$status".to_string()),
        representative: None,
        egress_rejections: Some(json!({"diagnostic": "x".repeat(8000)})),
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: vec!["request handling or dependency failure".to_string()],
        observed_target_fingerprint: "target-a".to_string(),
        attempt: 1,
        comparison_observation: None,
    }
}

fn configured_target() -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        target.path().join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(target.path().join(".gitignore"), ".traffic-e2e/local/\n").unwrap();
    for args in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "baseline",
        ],
        vec!["switch", "-qc", "fixture-work"],
    ] {
        let output = Command::new("git")
            .current_dir(target.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    target
}

fn context(root: &Path) -> RewriteContext {
    RewriteContext {
        target_root: root.to_path_buf(),
    }
}

fn api_state() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    inventory::install(&mut state, vec!["GET /api".to_string()]).unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(issue("issue-a"));
    state.attempt_delta = Some(RewriteAttemptDelta {
        previous_attempt: 0,
        current_attempt: 1,
        response_passed_delta: 0,
        response_nonpassing_delta: 2,
        improved: false,
        regressed: true,
    });
    state
}

#[test]
fn status_is_compact_and_overview_preserves_diagnostics_and_confirmation() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    let api = "GET /api".parse().unwrap();
    let scope = RewriteWorkScope::Api {
        api: "GET /api".into(),
    };
    let status =
        serde_json::to_value(status_rewrite_for_api(context(target.path()), None).unwrap())
            .unwrap();
    let scoped =
        serde_json::to_value(status_rewrite_for_api(context(target.path()), Some(&api)).unwrap())
            .unwrap();
    assert_eq!(status, scoped);
    assert_eq!(status["schema_version"], 32);
    assert_eq!(status["action"]["kind"], "implementation_required");
    assert_eq!(status["api_inventory"]["active"], 1);
    assert_eq!(status["api_inventory"]["total"], 1);
    assert!(serde_json::to_vec(&status).unwrap().len() < 3000);
    assert!(
        status["action"]["details"]
            .get("egress_rejections")
            .is_none()
    );
    assert_eq!(
        status["action"],
        serde_json::to_value(action::for_state(target.path(), &state)).unwrap()["action"]
    );
    assert!(status["action"]["commands"].get("evidence").is_none());
    let query_id = api_query_id(&state, state.active_issue.as_ref().unwrap());
    assert!(
        query_rewrite_evidence_for_scope(context(target.path()), &scope)
            .unwrap_err()
            .to_string()
            .contains("confirmed dedicated subagent")
    );
    assert!(
        query_rewrite_evidence(context(target.path()), &query_id)
            .unwrap_err()
            .to_string()
            .contains("confirmed dedicated subagent")
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );

    worker::confirm_current_for_test(&mut state);
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    let overview = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    assert_eq!(
        serde_json::to_value(&overview).unwrap(),
        serde_json::to_value(query_rewrite_evidence(context(target.path()), &query_id).unwrap())
            .unwrap()
    );
    let assignment = overview.context.as_ref().unwrap();
    assert_eq!(assignment.workflow_id, state.workflow_id);
    assert_eq!(assignment.recording_run_id, state.recording_run_id);
    assert_eq!(assignment.target_root, target.path());
    assert_eq!(assignment.require_comparison, state.require_comparison);
    assert_eq!(
        assignment.worker.dispatch_id,
        worker::dispatch_view(&state, scope, None).dispatch_id
    );
    assert_eq!(overview.query, "overview");
    assert_eq!(
        overview.facts["issue"],
        serde_json::to_value(state.active_issue.as_ref().unwrap()).unwrap()
    );
    assert_eq!(overview.facts["work_scope"]["api"], "GET /api");
    assert!(overview.applicable_rule_planners.is_empty());
    let delta = overview
        .queries
        .iter()
        .find(|q| q.query_id.ends_with("attempt-delta"))
        .unwrap();
    assert_eq!(delta.command.cwd, target.path());
    assert_eq!(delta.command.argv[2], target.path().to_str().unwrap());
    let report = query_rewrite_evidence(context(target.path()), &delta.query_id).unwrap();
    assert_eq!(report.facts["regressed"], true);
    assert!(report.queries.is_empty());
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
}

#[test]
fn overview_follows_parked_api_and_rejects_replaced_evidence() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    inventory::install(
        &mut state,
        vec!["GET /api".to_string(), "POST /other".to_string()],
    )
    .unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(issue("issue-a"));
    worker::confirm_current_for_test(&mut state);
    let original_id = api_query_id(&state, state.active_issue.as_ref().unwrap());
    inventory::activate_requested(&mut state, Some(&"POST /other".parse().unwrap())).unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(issue("issue-b"));
    worker::confirm_current_for_test(&mut state);
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    let overview = query_rewrite_evidence(context(target.path()), &original_id).unwrap();
    let scope = RewriteWorkScope::Api {
        api: "GET /api".into(),
    };
    let selected = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    assert_eq!(
        serde_json::to_value(&selected).unwrap(),
        serde_json::to_value(&overview).unwrap()
    );
    assert_eq!(selected.context.unwrap().worker.work_scope, scope);
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(overview.issue_id, "issue-a");
    assert_eq!(overview.facts["work_scope"]["api"], "GET /api");

    state
        .parked_slices
        .get_mut("GET /api")
        .unwrap()
        .active_issue
        .as_mut()
        .unwrap()
        .attempt += 1;
    store.save(&state).unwrap();
    assert!(
        query_rewrite_evidence_for_scope(context(target.path()), &scope)
            .unwrap_err()
            .to_string()
            .contains("confirmed dedicated subagent")
    );
    assert!(
        query_rewrite_evidence(context(target.path()), &original_id)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
}

#[test]
fn process_output_overview_is_scoped_confirmed_and_has_no_api_queries() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    let mut output_issue = issue("process-issue");
    output_issue.kind = RewriteIssueKind::ProcessOutput;
    output_issue.comparison_observation =
        Some(json!({"id": "metrics", "source_present": true, "target_present": false}));
    state.process_outputs.inventory = vec![RewriteProcessOutputProgress {
        id: "metrics".to_string(),
        status: RewriteProcessOutputStatus::ImplementationRequired,
        attempts: 1,
        verified_target_fingerprint: None,
        issue: Some(output_issue.clone()),
    }];
    state.process_outputs.current_id = Some("metrics".to_string());
    let action =
        serde_json::to_value(worker::implementation_action(target.path(), &state, None)).unwrap();
    assert!(action["details"].get("comparison_observation").is_none());
    assert!(action["commands"].get("evidence").is_none());
    let scope = RewriteWorkScope::ProcessOutput {
        id: "metrics".into(),
    };
    let query_id = super::query_id(&state, &scope, &output_issue);
    store.save(&state).unwrap();
    assert!(
        query_rewrite_evidence_for_scope(context(target.path()), &scope)
            .unwrap_err()
            .to_string()
            .contains("process output metrics requires a confirmed")
    );
    assert!(
        query_rewrite_evidence(context(target.path()), &query_id)
            .unwrap_err()
            .to_string()
            .contains("process output metrics requires a confirmed")
    );
    worker::confirm_current_for_test(&mut state);
    // Another current work item must not redirect this output's evidence.
    state.process_outputs.current_id = None;
    state.bump();
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    let overview = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    assert_eq!(
        serde_json::to_value(&overview).unwrap(),
        serde_json::to_value(query_rewrite_evidence(context(target.path()), &query_id).unwrap())
            .unwrap()
    );
    assert_eq!(overview.context.as_ref().unwrap().worker.work_scope, scope);
    assert_eq!(
        overview.facts["work_scope"],
        json!({"kind": "process_output", "id": "metrics"})
    );
    assert_eq!(
        overview.facts["issue"],
        serde_json::to_value(output_issue).unwrap()
    );
    assert!(overview.queries.is_empty());
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    state.recording_run_id = "replacement-recording".to_string();
    store.save(&state).unwrap();
    assert!(
        query_rewrite_evidence(context(target.path()), &query_id)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
}

#[test]
fn scope_queries_reject_unknown_items_and_items_without_issues() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    worker::confirm_current_for_test(&mut state);
    state
        .process_outputs
        .inventory
        .push(RewriteProcessOutputProgress {
            id: "metrics".into(),
            status: RewriteProcessOutputStatus::Complete,
            attempts: 1,
            verified_target_fingerprint: Some("target-a".into()),
            issue: None,
        });
    store.save(&state).unwrap();
    for (scope, expected) in [
        (
            RewriteWorkScope::Api {
                api: "GET /missing".into(),
            },
            "does not contain",
        ),
        (
            RewriteWorkScope::Api {
                api: "malformed".into(),
            },
            "recording API must use",
        ),
        (
            RewriteWorkScope::ProcessOutput {
                id: "missing".into(),
            },
            "does not contain",
        ),
        (
            RewriteWorkScope::ProcessOutput {
                id: "metrics".into(),
            },
            "no current issue",
        ),
    ] {
        let error = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        serde_json::to_value(&state).unwrap()
    );
    state.active_issue = None;
    store.save(&state).unwrap();
    let error = query_rewrite_evidence_for_scope(
        context(target.path()),
        &RewriteWorkScope::Api {
            api: "GET /api".into(),
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("no current issue"));
}

#[test]
fn overview_context_tracks_dispatch_without_invalidating_unchanged_evidence() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    let scope = RewriteWorkScope::Api {
        api: "GET /api".into(),
    };
    worker::confirm_current_for_test(&mut state);
    store.save(&state).unwrap();
    let original = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    state.bump();
    state
        .worker_bindings
        .get_mut("GET /api")
        .unwrap()
        .agent_name = Some("renamed-worker".into());
    store.save(&state).unwrap();
    let refreshed = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    assert_eq!(original.evidence_id, refreshed.evidence_id);
    assert_eq!(original.queries[0].query_id, refreshed.queries[0].query_id);
    assert!(
        refreshed.context.as_ref().unwrap().revision > original.context.as_ref().unwrap().revision
    );
    assert_eq!(
        refreshed
            .context
            .as_ref()
            .unwrap()
            .worker
            .agent_name
            .as_deref(),
        Some("renamed-worker")
    );

    state
        .worker_bindings
        .get_mut("GET /api")
        .unwrap()
        .rework_generation += 1;
    store.save(&state).unwrap();
    assert!(
        query_rewrite_evidence_for_scope(context(target.path()), &scope)
            .unwrap_err()
            .to_string()
            .contains("confirmed dedicated subagent")
    );
    worker::confirm_current_for_test(&mut state);
    store.save(&state).unwrap();
    let resumed = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    assert_ne!(
        original.context.as_ref().unwrap().worker.dispatch_id,
        resumed.context.as_ref().unwrap().worker.dispatch_id
    );
    assert_eq!(
        original.context.as_ref().unwrap().worker.binding_id,
        resumed.context.as_ref().unwrap().worker.binding_id
    );
    assert_eq!(original.issue_id, resumed.issue_id);
    assert_eq!(original.evidence_id, resumed.evidence_id);
}
