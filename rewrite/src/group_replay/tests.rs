use super::*;
use crate::{
    api_batch, implementer::ImplementerPool, repository_analysis::RepositoryAnalysisSnapshot,
};

pub(super) fn state(apis: &[&str], groups: &[(&str, &str)]) -> RewriteState {
    let mut state = crate::test_state();
    inventory::install(&mut state, apis.iter().map(|api| (*api).into()).collect()).unwrap();
    state.implementers = Some(ImplementerPool::new(16));
    state.repository_analysis = Some(RepositoryAnalysisSnapshot {
        catalog_revision: "test-analysis".into(),
        api_groups: groups
            .iter()
            .map(|(api, group)| ((*api).into(), (*group).into()))
            .collect(),
    });
    state
}

pub(super) fn result(api: &str, passed: bool) -> crate::E2eApiRunResult {
    serde_json::from_value(serde_json::json!({
        "engine_fingerprint": crate::build_info::ENGINE_FINGERPRINT,
        "run_key": "test-replay", "api": api, "attempt": 1,
        "status": if passed { "successful" } else { "failed" }, "passed": passed,
        "gates": { "responses": if passed { "passed" } else { "nonpassing" },
            "replay": "complete", "dependencies": "clean" },
        "diagnosis": { "counts": { "selected": 1, "executed": 1,
            "response_passed": u32::from(passed), "response_nonpassing": u32::from(!passed), "response_incomplete": 0 },
            "response_differences": { "total_differences": 0, "indexed_differences": 0, "omitted_differences": 0,
                "failure_clusters": [], "omitted_failure_clusters": 0 }, "representative": null },
        "progress": ".traffic-e2e/progress.yaml"
    })).unwrap()
}

#[test]
fn initial_round_finishes_every_group_route_before_dispatching_failures() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = state(
        &["GET /a", "POST /a", "GET /other", "GET /b"],
        &[("/a", "auth"), ("/b", "auth"), ("/other", "other")],
    );
    assert!(prepare(root, &mut state, "/a").unwrap());
    let round = state.group_replay.as_ref().unwrap();
    assert_eq!(round.routes, ["/a", "/b"]);
    assert_eq!(round.methods["/a"], ["GET /a", "POST /a"]);
    api_batch::apply_results(
        root,
        &mut state,
        &[result("GET /a", false), result("POST /a", true)],
        None,
    )
    .unwrap();
    assert!(after_replay(root, &mut state, "/a").unwrap());
    assert_eq!(state.api, "GET /b");
    assert!(!dispatch_ready(&state, "/a"));
    assert!(
        matches!(action(root, &state), Some(RewriteAction::AdvanceRequired { api: Some(api), .. }) if api == "/b")
    );

    api_batch::apply_results(root, &mut state, &[result("GET /b", false)], None).unwrap();
    assert!(!after_replay(root, &mut state, "/b").unwrap());
    assert!(state.group_replay.is_none());
    let summary = state.last_group_replay.as_ref().unwrap();
    assert!(summary.complete);
    assert_eq!(summary.results.len(), 2);
    assert!(summary.results.iter().all(|result| !result.passed));
    assert!(dispatch_ready(&state, "/a"));
    assert!(dispatch_ready(&state, "/b"));
    assert!(!dispatch_ready(&state, "/other"));
}

#[test]
fn acceptance_round_freezes_only_exact_admitted_methods() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = state(
        &["GET /a", "POST /a", "GET /b"],
        &[("/a", "auth"), ("/b", "auth")],
    );
    api_batch::apply_results(
        root,
        &mut state,
        &[result("GET /a", false), result("POST /a", false)],
        None,
    )
    .unwrap();
    state.rule_replay_pending = true;
    assert_eq!(state.api, "GET /a");
    assert!(prepare(root, &mut state, "/a").unwrap());
    let round = state.group_replay.as_ref().unwrap();
    assert_eq!(round.kind, GroupReplayKind::Acceptance);
    assert_eq!(round.routes, ["/a"]);
    assert_eq!(round.methods["/a"], ["GET /a"]);
    assert!(planned_method(&state, "GET /a"));
    assert!(!planned_method(&state, "POST /a"));
    let mut batch = api_batch::PreparedRoute {
        apis: vec!["GET /a".into(), "POST /a".into()],
        slices: BTreeMap::new(),
    };
    restrict(&state, &mut batch).unwrap();
    assert_eq!(batch.apis, ["GET /a"]);
    assert!(!dispatch_ready(&state, "/b"));
}

#[test]
fn interrupted_round_restores_without_replaying_completed_routes() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = state(&["GET /a", "GET /b"], &[("/a", "auth"), ("/b", "auth")]);
    prepare(root, &mut state, "/a").unwrap();
    api_batch::apply_results(root, &mut state, &[result("GET /a", false)], None).unwrap();
    after_replay(root, &mut state, "/a").unwrap();
    interrupted(&mut state, &anyhow::anyhow!("target startup unavailable"));
    assert!(!state.last_group_replay.as_ref().unwrap().complete);
    assert_eq!(state.last_group_replay.as_ref().unwrap().remaining, ["/b"]);
    let mut restored: RewriteState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(prepare(root, &mut restored, "/b").unwrap());
    assert_eq!(restored.group_replay.as_ref().unwrap().next(), Some("/b"));
    assert_eq!(restored.group_replay.as_ref().unwrap().results.len(), 1);
    assert!(prepare(root, &mut restored, "/a").is_err());
}

#[test]
fn identity_change_archives_partial_round_and_reselects_remaining_work() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = state(&["GET /a", "GET /b"], &[("/a", "auth"), ("/b", "auth")]);
    prepare(root, &mut state, "/a").unwrap();
    api_batch::apply_results(root, &mut state, &[result("GET /a", false)], None).unwrap();
    after_replay(root, &mut state, "/a").unwrap();
    state.group_replay.as_mut().unwrap().target_fingerprint = "outdated".into();
    prepare(root, &mut state, "/b").unwrap();
    assert_eq!(state.group_replay.as_ref().unwrap().routes, ["/b"]);
    let archived = state.last_group_replay.as_ref().unwrap();
    assert_eq!(archived.results.len(), 1);
    assert!(archived.interruption.is_some());
}

#[test]
fn ungrouped_apis_are_blocked_and_legacy_workflows_keep_single_api_behavior() {
    let target = crate::worker::tests::configured_target();
    let mut state = state(&["GET /a"], &[]);
    assert!(!dispatch_ready(&state, "/a"));
    assert!(prepare(target.path(), &mut state, "/a").is_err());
    state.implementers = None;
    assert!(dispatch_ready(&state, "/a"));
    assert!(!prepare(target.path(), &mut state, "/a").unwrap());
}

#[test]
fn skipped_methods_do_not_hold_up_group_dispatch() {
    let mut state = state(&["GET /a", "POST /a"], &[("/a", "auth")]);
    state.phase = RewritePhase::ImplementationRequired;
    state.api_inventory[0].status = RewriteApiStatus::ImplementationRequired;
    state.api_inventory[1].status = RewriteApiStatus::Skipped;
    assert!(dispatch_ready(&state, "/a"));
}

#[test]
fn target_change_resumes_pending_refresh_with_prior_attempts() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = state(&["GET /a"], &[("/a", "auth")]);
    api_batch::apply_results(root, &mut state, &[result("GET /a", false)], None).unwrap();
    assert_eq!(state.phase, RewritePhase::ImplementationRequired);
    assert_eq!(state.attempts.len(), 1);
    assert!(!pending_replay(&state, "GET /a"));
    state.rule_replay_pending = true;
    prepare(root, &mut state, "/a").unwrap();
    assert_eq!(
        state.group_replay.as_ref().unwrap().kind,
        GroupReplayKind::Acceptance
    );
    let previous = state
        .group_replay
        .as_ref()
        .unwrap()
        .target_fingerprint
        .clone();

    // Match verification's invalidation when the target changes during execution.
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    state.phase = RewritePhase::ApiPending;
    state.target_fingerprint = None;
    state.active_issue = None;
    state.rule_replay_pending = false;
    state.e2e_current = false;
    assert_eq!(state.attempts.len(), 1);
    assert!(pending_replay(&state, "GET /a"));

    assert!(prepare(root, &mut state, "/a").unwrap());
    let restored = state.group_replay.as_ref().unwrap();
    assert_eq!(restored.kind, GroupReplayKind::Initial);
    assert_eq!(restored.routes, ["/a"]);
    assert_eq!(restored.methods["/a"], ["GET /a"]);
    assert_ne!(restored.target_fingerprint, previous);
    assert_eq!(state.attempts.len(), 1);
    assert!(
        state
            .last_group_replay
            .as_ref()
            .unwrap()
            .interruption
            .is_some()
    );
}

#[test]
fn restored_round_archives_excluded_next_api_and_can_resume_remaining_routes() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = state(
        &["GET /a", "GET /b", "GET /c"],
        &[("/a", "auth"), ("/b", "auth"), ("/c", "auth")],
    );
    prepare(root, &mut state, "/a").unwrap();
    api_batch::apply_results(root, &mut state, &[result("GET /a", false)], None).unwrap();
    after_replay(root, &mut state, "/a").unwrap();
    let mut restored: RewriteState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    restored
        .api_inventory
        .iter_mut()
        .find(|item| item.api == "GET /b")
        .unwrap()
        .status = RewriteApiStatus::Skipped;
    crate::regression_scope::apply(root, &mut restored).unwrap();
    assert!(refresh(&mut restored));
    assert!(restored.group_replay.is_none());
    assert!(action(root, &restored).is_none());
    let archived = restored.last_group_replay.as_ref().unwrap();
    assert_eq!(archived.results.len(), 1);
    assert_eq!(archived.results[0].api, "/a");
    assert!(!archived.results[0].passed);
    assert_eq!(archived.remaining, ["/b", "/c"]);
    assert!(!archived.complete);
    assert!(archived.interruption.is_some());
    inventory::activate_requested(&mut restored, Some(&"GET /c".parse().unwrap())).unwrap();
    prepare(root, &mut restored, "/c").unwrap();
    assert_eq!(restored.group_replay.as_ref().unwrap().routes, ["/c"]);
    assert!(!refresh(&mut restored));
}

#[test]
fn frozen_round_is_retired_when_recording_inventory_or_group_identity_changes() {
    let target = crate::worker::tests::configured_target();
    let mut original = state(&["GET /a", "GET /b"], &[("/a", "auth"), ("/b", "auth")]);
    prepare(target.path(), &mut original, "/a").unwrap();
    for mutation in 0..5 {
        let mut state = original.clone();
        match mutation {
            0 => state.recording_run_id = "20261018000000".into(),
            1 => state.api_inventory.clear(),
            2 => state.phase = RewritePhase::RecordingRequired,
            3 => {
                state.api_inventory.pop();
            }
            _ => {
                state
                    .repository_analysis
                    .as_mut()
                    .unwrap()
                    .api_groups
                    .insert("/b".into(), "other".into());
            }
        }
        assert!(refresh(&mut state));
        assert!(state.group_replay.is_none());
        assert!(
            state
                .last_group_replay
                .as_ref()
                .unwrap()
                .interruption
                .is_some()
        );
        assert!(!state.last_group_replay.as_ref().unwrap().complete);
    }
}
