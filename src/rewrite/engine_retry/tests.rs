use super::*;
mod active_worker;
mod final_route;

fn traditional_pending(slice: &RewriteSliceState) -> bool {
    eligible(slice, crate::build_info::ENGINE_FINGERPRINT)
}

use crate::rewrite::{
    self, RewriteAction, RewriteWorkScope, action, api_selector, inventory,
    model::{RewriteApiStatus, RewriteIssueOwner},
    replay_admission,
    store::RewriteStore,
    worker,
};

fn runtime_state(engine: Option<&str>) -> RewriteState {
    let mut state = worker::tests::implementation_state_with_inventory(false);
    let issue = state.active_issue.as_mut().unwrap();
    issue.kind = RewriteIssueKind::TargetRuntime;
    issue.owner = RewriteIssueOwner::TargetRuntime;
    state.attempts.push(serde_json::from_value(serde_json::json!({
        "engine_fingerprint": engine,
        "attempt": 1, "passed": false,
        "gates": { "responses": "incomplete", "replay": "incomplete", "dependencies": "unknown" },
        "counts": { "selected": 1, "executed": 0, "response_passed": 0,
            "response_nonpassing": 0, "response_incomplete": 1 }
    })).unwrap());
    state
}

fn sibling(state: &mut RewriteState, api: &str, kind: RewriteIssueKind) {
    let mut slice = state.active_slice.clone();
    slice.api = api.into();
    slice.source_route = api_selector::route(api).into();
    slice.active_issue.as_mut().unwrap().kind = kind;
    let mut item = state.api_inventory[0].clone();
    item.api = api.into();
    item.source_route = Some(slice.source_route.clone());
    item.status = RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(item);
    state.parked_slices.insert(api.into(), slice);
}

#[test]
fn changed_engine_and_legacy_attempts_get_one_permit_without_target_changes() {
    let current = crate::build_info::ENGINE_FINGERPRINT;
    for previous in [None, Some("engine-revision-v1:older")] {
        let mut state = runtime_state(previous);
        let original_issue = serde_json::to_value(&state.active_issue).unwrap();
        assert!(eligible(&state.active_slice, current));
        if let Some(previous) = previous {
            assert!(!eligible(&state.active_slice, previous));
        }
        assert!(consume(&mut state.active_slice, false));
        assert!(!consume(&mut state.active_slice, false));
        assert!(!traditional_pending(&state.active_slice));
        assert_eq!(
            serde_json::to_value(&state.active_issue).unwrap(),
            original_issue
        );
        assert!(!state.e2e_current);
        assert_eq!(state.attempts.len(), 1);
        clear_running(&mut state);
        // Another committed engine may get one chance; returning to this one cannot.
        assert!(eligible(&state.active_slice, "engine-revision-v1:later"));
        assert!(!eligible(&state.active_slice, current));
    }
    assert!(!traditional_pending(
        &runtime_state(Some(current)).active_slice
    ));
}

fn partial_response_state() -> RewriteState {
    let mut state = runtime_state(Some("engine-revision-v1:older"));
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::TargetCode;
    state.attempts[0].counts.selected = 16;
    state.attempts[0].counts.executed = 2;
    state.attempts[0].counts.response_nonpassing = 2;
    state.attempts[0].counts.response_incomplete = 14;
    state.attempts[0].gates.responses = crate::E2eResponseGate::Nonpassing;
    state
}

#[test]
fn interrupted_response_can_refresh_while_an_unrelated_implementation_stays_parked() {
    let target = worker::tests::configured_target();
    let mut state = partial_response_state();
    sibling(&mut state, "POST /socket.io/", RewriteIssueKind::Response);
    let parked = state.parked_slices.get_mut("POST /socket.io/").unwrap();
    parked.attempts[0].counts.executed = 16;
    parked.attempts[0].gates.replay = crate::E2eReplayGate::Complete;
    let parked_before = serde_json::to_value(&state.parked_slices).unwrap();
    let issue_before = serde_json::to_value(&state.active_issue).unwrap();
    assert!(!last_unfinished_route(&state, &state.api));
    assert!(pending(&state, &state.active_slice));
    let scope = api_selector::work_scope(&state, &state.api);
    assert!(worker::scheduler::acceptance_gate(target.path(), &state, &scope).is_none());
    assert!(!worker::runtime::scopes(&state).contains(&scope));
    assert!(
        worker::runtime::scopes(&state)
            .contains(&api_selector::work_scope(&state, "POST /socket.io/"))
    );
    assert!(consume(&mut state.active_slice, false));
    assert!(!consume(&mut state.active_slice, false));
    assert_eq!(
        serde_json::to_value(&state.active_issue).unwrap(),
        issue_before
    );
    assert_eq!(
        serde_json::to_value(&state.parked_slices).unwrap(),
        parked_before
    );
}

#[test]
fn interrupted_response_retry_does_not_release_complete_unknown_or_quality_failures() {
    let current = crate::build_info::ENGINE_FINGERPRINT;
    for variant in 0..6 {
        let mut state = partial_response_state();
        match variant {
            0 => state.attempts[0].engine_fingerprint = Some(current.into()),
            1 => state.attempts[0].engine_fingerprint = None,
            2 => state.attempts[0].counts.executed = state.attempts[0].counts.selected,
            3 => state.attempts[0].counts.executed = 0,
            4 => state.attempts[0].gates.replay = crate::E2eReplayGate::Complete,
            _ => state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::TargetQuality,
        }
        assert!(!eligible(&state.active_slice, current), "variant {variant}");
    }
}

#[test]
fn only_runtime_issues_with_a_matching_failed_attempt_are_eligible() {
    for kind in [
        RewriteIssueKind::Response,
        RewriteIssueKind::Dependency,
        RewriteIssueKind::Replay,
        RewriteIssueKind::TargetQuality,
    ] {
        let mut state = runtime_state(None);
        state.active_issue.as_mut().unwrap().kind = kind;
        assert!(!traditional_pending(&state.active_slice), "{kind:?}");
    }
    for phase in [
        RewritePhase::ApiPending,
        RewritePhase::SliceComplete,
        RewritePhase::RecordingRequired,
        RewritePhase::SystemRepairRequired,
        RewritePhase::AwaitingRecordingRefresh,
    ] {
        let mut state = runtime_state(None);
        state.phase = phase;
        assert!(!traditional_pending(&state.active_slice), "{phase:?}");
    }
    let mut state = runtime_state(None);
    state.attempts[0].passed = true;
    assert!(!traditional_pending(&state.active_slice));
    state.attempts[0].passed = false;
    state.active_issue.as_mut().unwrap().attempt = 2;
    assert!(!traditional_pending(&state.active_slice));
    state.attempts.clear();
    assert!(!traditional_pending(&state.active_slice));
}

#[test]
fn target_changes_and_same_commit_rebuilds_do_not_grant_an_engine_retry() {
    let mut state = runtime_state(Some(crate::build_info::ENGINE_FINGERPRINT));
    state.target_fingerprint = Some("new-target".into());
    state
        .active_issue
        .as_mut()
        .unwrap()
        .observed_target_fingerprint = "old-target".into();
    assert!(!traditional_pending(&state.active_slice));
}

#[tokio::test]
async fn recovery_clears_a_crashed_retry_without_refunding_its_permit() {
    let target = worker::tests::configured_target();
    let mut state = runtime_state(None);
    reserve(&mut state, None);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    rewrite::recover_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .await
    .unwrap();
    let recovered = store.load().unwrap().unwrap();
    assert!(!recovered.engine_retry_running);
    assert!(!traditional_pending(&recovered.active_slice));
    assert_eq!(recovered.attempts.len(), 1);
    assert_eq!(worker::runtime::scopes(&recovered).len(), 1);
}

#[tokio::test]
async fn execution_preflight_error_keeps_the_consumed_permit_and_releases_running_state() {
    let target = worker::tests::configured_target();
    let mut state = runtime_state(None);
    state.case_source = Some(target.path().join("missing-recording"));
    state.group_id = Some(state.api.clone());
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    // Missing target Dockerfile/recording fails preflight before Docker can run.
    let error = rewrite::verification::run_and_transition(target.path(), &mut state, false)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("ignored") || error.to_string().contains("Dockerfile"),
        "{error:#}"
    );
    let restored = store.load().unwrap().unwrap();
    assert!(
        restored
            .engine_retry_fingerprints
            .contains(crate::build_info::ENGINE_FINGERPRINT)
    );
    assert!(!restored.engine_retry_running);
    assert!(!traditional_pending(&restored.active_slice));
    assert_eq!(restored.attempts.len(), 1);
    assert_eq!(worker::runtime::scopes(&restored).len(), 1);
}

#[test]
fn running_retry_keeps_status_waiting_instead_of_dispatching_the_old_issue() {
    let target = worker::tests::configured_target();
    let mut state = runtime_state(None);
    assert!(reserve(&mut state, None));
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let claim = rewrite::traffic_operation::claim_current(
        target.path(),
        "runtime-retry".into(),
        rewrite::traffic_operation::TrafficOperationKind::Replay,
        Some(state.api.clone()),
    )
    .unwrap();
    let rewrite::traffic_operation::TrafficOperationClaim::Acquired(_guard) = claim else {
        panic!("lease")
    };
    let status = rewrite::status_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(
        matches!(status.action, RewriteAction::WaitRequired { .. }),
        "{:?}",
        status.action
    );
    assert!(worker::runtime::scopes(&state).is_empty());
}

#[test]
fn consumed_legacy_retry_survives_restart_even_without_a_new_result() {
    let target = worker::tests::configured_target();
    let mut value = serde_json::to_value(runtime_state(None)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("engine_retry_fingerprints");
    value["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("engine_fingerprint");
    let mut state: RewriteState = serde_json::from_value(value).unwrap();
    assert!(traditional_pending(&state.active_slice));
    assert!(reserve(&mut state, None));
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let mut restored = store.load().unwrap().unwrap();
    assert!(!traditional_pending(&restored.active_slice));
    assert_eq!(restored.attempts.len(), 1);
    assert_eq!(restored.active_issue.as_ref().unwrap().attempt, 1);
    assert!(worker::runtime::scopes(&restored).is_empty());
    assert!(clear_running(&mut restored));
    assert_eq!(worker::runtime::scopes(&restored).len(), 1);
    assert!(!traditional_pending(&restored.active_slice));
}

#[test]
fn status_is_read_only_and_keeps_delivery_review_without_worker_handoff() {
    let target = worker::tests::configured_target();
    let state = runtime_state(None);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let before = serde_json::to_value(store.load().unwrap()).unwrap();
    for _ in 0..3 {
        let status = rewrite::status_rewrite(crate::RewriteContext {
            target_root: target.path().into(),
        })
        .unwrap();
        assert!(
            matches!(status.action, RewriteAction::SourceReviewRequired { .. }),
            "{:?}",
            status.action
        );
        assert!(!status.terminal_allowed);
        assert_eq!(serde_json::to_value(store.load().unwrap()).unwrap(), before);
    }
    assert!(worker::runtime::scopes(&state).is_empty());
    assert!(
        worker::scheduler::acceptance_gate(
            target.path(),
            &state,
            &RewriteWorkScope::Api {
                api: state.api.clone()
            }
        )
        .is_none()
    );
    let details = rewrite::coordination::status_details(target.path(), &state).unwrap();
    assert!(!details.ready.contains_key("resume_worker"));
    assert!(!details.ready.contains_key("dispatch_worker"));
    assert_eq!(details.ready.get("target_quality"), Some(&1));
}

#[tokio::test]
async fn next_keeps_review_gate_and_does_not_consume_a_retry_before_admission() {
    let target = worker::tests::configured_target();
    let state = runtime_state(Some("engine-revision-v1:old"));
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let next = rewrite::next_rewrite(crate::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        next.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    assert!(traditional_pending(
        &store.load().unwrap().unwrap().active_slice
    ));
}

#[test]
fn method_retry_does_not_release_an_unaccepted_sibling_and_parked_retries_are_visible() {
    let target = worker::tests::configured_target();
    let mut state = runtime_state(None);
    sibling(&mut state, "PUT /api", RewriteIssueKind::Response);
    let route = api_selector::work_scope(&state, &state.api);
    assert!(!replay_admission::admitted(&state, &route));
    assert!(replay_admission::admitted(
        &state,
        &RewriteWorkScope::Api {
            api: "GET /api".into()
        }
    ));
    assert_eq!(worker::runtime::scopes(&state), vec![route]);
    // Route selection picks a runnable method even if its sibling is active.
    inventory::resume_at(&mut state, 1).unwrap();
    assert_eq!(
        api_selector::select(&state, &"/api".parse().unwrap())
            .unwrap()
            .to_string(),
        "GET /api"
    );
    sibling(&mut state, "GET /parked", RewriteIssueKind::TargetRuntime);
    let selected = rewrite::scheduling::idle_action(target.path(), &state).unwrap();
    assert!(matches!(selected, RewriteAction::AdvanceRequired { .. }));
}

#[test]
fn route_reservation_persists_every_selected_method_before_execution() {
    let target = worker::tests::configured_target();
    let mut state = runtime_state(None);
    sibling(&mut state, "PUT /api", RewriteIssueKind::TargetRuntime);
    let mut prepared = rewrite::api_batch::PreparedRoute {
        apis: vec!["GET /api".into(), "PUT /api".into()],
        slices: std::iter::once((state.api.clone(), state.active_slice.clone()))
            .chain(state.parked_slices.clone())
            .collect(),
    };
    assert!(replay_admission::admitted(
        &state,
        &api_selector::work_scope(&state, &state.api)
    ));
    assert!(reserve(&mut state, Some(&mut prepared)));
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let restored = store.load().unwrap().unwrap();
    assert!(!traditional_pending(&restored.active_slice));
    assert!(!traditional_pending(&restored.parked_slices["PUT /api"]));
    assert!(
        prepared
            .slices
            .values()
            .all(|slice| !traditional_pending(slice))
    );
    assert!(!reserve(&mut state, Some(&mut prepared)));
}

#[test]
fn new_pass_and_runtime_failure_keep_the_actual_executor_identity_and_consume_the_permit() {
    let target = worker::tests::configured_target();
    for passed in [false, true] {
        let mut state = runtime_state(None);
        assert!(consume(&mut state.active_slice, false));
        let result = serde_json::from_value(serde_json::json!({
            "engine_fingerprint": crate::build_info::ENGINE_FINGERPRINT,
            "run_key": "recording", "api": state.api, "attempt": 2,
            "status": if passed { "successful" } else { "interrupted" }, "passed": passed,
            "gates": { "responses": if passed { "passed" } else { "incomplete" },
                "replay": if passed { "complete" } else { "incomplete" },
                "dependencies": if passed { "clean" } else { "unknown" } },
            "diagnosis": { "counts": { "selected": 1, "executed": usize::from(passed),
                "response_passed": usize::from(passed), "response_nonpassing": 0,
                "response_incomplete": usize::from(!passed) },
                "response_differences": { "total_differences": 0, "indexed_differences": 0,
                    "omitted_differences": 0, "failure_clusters": [], "omitted_failure_clusters": 0 },
                "representative": null, "lifecycle_errors": if passed { vec![] } else { vec!["runner failed"] } },
            "progress": "unused.yaml"
        })).unwrap();
        rewrite::transition::from_e2e_result(
            target.path(),
            &mut state,
            &result,
            rewrite::transition::AttemptTransition::Append,
        )
        .unwrap();
        assert_eq!(state.attempts.len(), 2);
        assert_eq!(
            state.attempts[1].engine_fingerprint.as_deref(),
            Some(crate::build_info::ENGINE_FINGERPRINT)
        );
        assert!(!traditional_pending(&state.active_slice));
        if passed {
            assert!(state.active_issue.is_none());
            assert_eq!(state.phase, RewritePhase::SliceComplete);
        } else {
            assert_eq!(
                state.active_issue.as_ref().unwrap().kind,
                RewriteIssueKind::TargetRuntime
            );
            assert_eq!(state.active_issue.as_ref().unwrap().attempt, 2);
            assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        }
    }
}

#[test]
fn skips_and_active_traffic_are_not_replayed_by_status() {
    let target = worker::tests::configured_target();
    let mut state = runtime_state(None);
    state.api_inventory[0].status = RewriteApiStatus::Skipped;
    assert!(!any_pending(&state));
    assert!(worker::runtime::scopes(&state).is_empty());
    state.api_inventory[0].status = RewriteApiStatus::Active;
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let claim = rewrite::traffic_operation::claim_current(
        target.path(),
        "test-replay".into(),
        rewrite::traffic_operation::TrafficOperationKind::Replay,
        Some(state.api.clone()),
    )
    .unwrap();
    let rewrite::traffic_operation::TrafficOperationClaim::Acquired(_guard) = claim else {
        panic!("lease")
    };
    let status = rewrite::status_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(!matches!(
        status.action,
        RewriteAction::AdvanceRequired { .. }
    ));
    assert!(traditional_pending(
        &RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
            .active_slice
    ));
    assert!(matches!(
        action::for_state(target.path(), &state).action,
        RewriteAction::AdvanceRequired { .. }
    ));
}

fn dependency_state(engine: Option<&str>) -> RewriteState {
    let mut state = runtime_state(engine);
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Dependency;
    state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
    state.attempts[0].gates = crate::E2eVerificationGates {
        responses: crate::E2eResponseGate::Passed,
        replay: crate::E2eReplayGate::Complete,
        dependencies: crate::E2eDependencyGate::Dirty,
    };
    state.attempts[0].counts.executed = 1;
    state.attempts[0].counts.response_passed = 1;
    state.attempts[0].counts.response_incomplete = 0;
    state
}

#[test]
fn dependency_only_failures_get_one_durable_retry_after_an_engine_change() {
    let target = worker::tests::configured_target();
    for old in [None, Some("engine-revision-v1:older")] {
        let mut state = dependency_state(old);
        let issue = serde_json::to_value(&state.active_issue).unwrap();
        let current = crate::build_info::ENGINE_FINGERPRINT;
        assert!(traditional_pending(&state.active_slice));
        assert!(worker::runtime::scopes(&state).is_empty());
        let scope = api_selector::work_scope(&state, &state.api);
        assert!(replay_admission::admitted(&state, &scope));
        assert!(matches!(
            action::state_action(target.path(), &state),
            RewriteAction::AdvanceRequired { .. }
        ));
        assert!(reserve(&mut state, None));
        let store = RewriteStore::new(target.path()).unwrap();
        store.save(&state).unwrap();
        let mut restored = store.load().unwrap().unwrap();
        clear_running(&mut restored);
        assert!(!traditional_pending(&restored.active_slice));
        assert!(restored.engine_retry_fingerprints.contains(current));
        assert_eq!(serde_json::to_value(&restored.active_issue).unwrap(), issue);
        assert_eq!(restored.attempts.len(), 1);
        assert!(!restored.e2e_current);
        assert!(eligible(&restored.active_slice, "engine-revision-v1:next"));
    }
    assert!(!traditional_pending(
        &dependency_state(Some(crate::build_info::ENGINE_FINGERPRINT)).active_slice
    ));
}

#[test]
fn dependency_retry_requires_complete_passing_responses_and_only_dirty_dependencies() {
    for mode in 0..9 {
        let mut state = dependency_state(None);
        let a = &mut state.attempts[0];
        match mode {
            0 => a.gates.responses = crate::E2eResponseGate::Nonpassing,
            1 => a.gates.responses = crate::E2eResponseGate::Incomplete,
            2 => a.gates.replay = crate::E2eReplayGate::Incomplete,
            3 => a.gates.dependencies = crate::E2eDependencyGate::Unknown,
            4 => a.counts.executed = 0,
            5 => a.counts.response_nonpassing = 1,
            6 => a.counts.response_incomplete = 1,
            7 => a.counts.response_passed = 0,
            _ => a.gates.dependencies = crate::E2eDependencyGate::Clean,
        }
        assert!(!traditional_pending(&state.active_slice), "mode={mode}");
    }
}

#[test]
fn dependency_retry_admits_each_route_method_independently_without_worker_reclassification() {
    let mut state = dependency_state(Some("old-engine"));
    sibling(&mut state, "OPTIONS /api", RewriteIssueKind::Dependency);
    let scope = api_selector::work_scope(&state, &state.api);
    assert!(replay_admission::admitted(&state, &scope));
    assert!(worker::runtime::scopes(&state).is_empty());
    state
        .parked_slices
        .get_mut("OPTIONS /api")
        .unwrap()
        .attempts[0]
        .engine_fingerprint = Some(crate::build_info::ENGINE_FINGERPRINT.into());
    assert!(!replay_admission::admitted(&state, &scope));
    assert_eq!(worker::runtime::scopes(&state), vec![scope]);
    assert!(replay_admission::admitted(
        &state,
        &RewriteWorkScope::Api {
            api: "GET /api".into()
        }
    ));
}
