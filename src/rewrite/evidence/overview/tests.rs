use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::json;

use super::*;
use crate::rewrite::model::{
    RewriteAttemptDelta, RewriteIssueKind, RewriteIssueOwner, RewritePhase,
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
    let scope = RewriteWorkScope::Api { api: "/api".into() };
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
    assert_eq!(overview.facts["work_scope"]["api"], "/api");

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
fn overview_context_tracks_dispatch_without_invalidating_unchanged_evidence() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    let scope = RewriteWorkScope::Api { api: "/api".into() };
    worker::confirm_current_for_test(&mut state);
    store.save(&state).unwrap();
    let original = query_rewrite_evidence_for_scope(context(target.path()), &scope).unwrap();
    state.bump();
    state.worker_bindings.get_mut("/api").unwrap().agent_name = Some("renamed-worker".into());
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
        .get_mut("/api")
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

#[test]
fn status_is_compact_and_overview_preserves_diagnostics_and_confirmation() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = api_state();
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    let api = "GET /api".parse().unwrap();
    let scope = RewriteWorkScope::Api { api: "/api".into() };
    let status =
        serde_json::to_value(status_rewrite_for_api(context(target.path()), None).unwrap())
            .unwrap();
    let scoped =
        serde_json::to_value(status_rewrite_for_api(context(target.path()), Some(&api)).unwrap())
            .unwrap();
    assert_eq!(status, scoped);
    assert_eq!(status["schema_version"], 39);
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
    assert_eq!(
        assignment.worker.dispatch_id,
        worker::dispatch_view(&state, scope, None).dispatch_id
    );
    assert_eq!(overview.query, "overview");
    assert_eq!(
        overview.facts["issue"],
        serde_json::to_value(state.active_issue.as_ref().unwrap()).unwrap()
    );
    assert_eq!(overview.facts["work_scope"]["api"], "/api");
    assert!(overview.applicable_rule_planners.is_empty());
    let discovery = overview
        .queries
        .iter()
        .find(|query| {
            super::super::is_rule_discovery_query(
                &state,
                state.active_issue.as_ref().unwrap(),
                &query.query_id,
            )
        })
        .unwrap();
    assert!(
        !discovery
            .purpose
            .starts_with("Discover bounded typed rule drafts")
    );
    assert_eq!(overview.facts["rule_discovery"], json!([discovery]));
    let hint = overview
        .rule_hints
        .iter()
        .find(|hint| hint.capability == "unified_value_contract")
        .unwrap();
    assert_eq!(hint.help.argv, discovery.command.argv);
    assert!(
        hint.hint.len() < 400,
        "ordinary guidance remains bounded; capabilities are queried on demand"
    );
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
    assert!(
        report
            .rule_hints
            .iter()
            .any(|hint| hint.capability == "unified_value_contract"
                && hint.help.argv == discovery.command.argv)
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
}

#[test]
fn overview_discovers_each_method_by_query_identity_instead_of_human_purpose() {
    let target = configured_target();
    let mut state = api_state();
    inventory::install(&mut state, vec!["GET /api".into(), "POST /api".into()]).unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(issue("get-issue"));
    worker::confirm_current_for_test(&mut state);
    inventory::activate_requested(&mut state, Some(&"POST /api".parse().unwrap())).unwrap();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(issue("post-issue"));
    worker::confirm_current_for_test(&mut state);
    let selected_issue = state.active_issue.as_ref().unwrap();
    let report = super::report(
        target.path(),
        &state,
        RewriteWorkScope::Api { api: "/api".into() },
        selected_issue,
        &api_query_id(&state, selected_issue),
    )
    .unwrap();
    let queries = report.facts["rule_discovery"].as_array().unwrap();
    assert_eq!(queries.len(), 2);
    let ids = queries
        .iter()
        .map(|query| query["query_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 2);
    assert!(
        report
            .queries
            .iter()
            .filter(|query| ids.contains(query.query_id.as_str()))
            .count()
            == 2
    );
    for query in queries {
        assert_eq!(query["command"]["cwd"], json!(target.path()));
    }
}
