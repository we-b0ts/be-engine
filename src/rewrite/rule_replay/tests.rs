use super::*;

#[test]
fn a_rule_for_one_method_does_not_release_the_worker_for_another_dirty_method() {
    let mut state = crate::rewrite::worker::tests::implementation_state_with_inventory(false);
    let mut sibling = state.active_slice.clone();
    sibling.api = "PUT /api".into();
    sibling.active_issue.as_mut().unwrap().id = "put-issue".into();
    let mut progress = state.api_inventory[0].clone();
    progress.api = sibling.api.clone();
    progress.status = crate::rewrite::model::RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(progress);
    state.parked_slices.insert(sibling.api.clone(), sibling);
    request(&mut state);
    let scope = crate::rewrite::api_selector::work_scope(&state, &state.api);
    assert!(!ready(&state, &scope));
    assert_eq!(
        crate::rewrite::worker::runtime::scopes(&state),
        vec![scope.clone()]
    );
    state
        .parked_slices
        .get_mut("PUT /api")
        .unwrap()
        .rule_replay_pending = true;
    assert!(ready(&state, &scope));
    assert!(crate::rewrite::worker::runtime::scopes(&state).is_empty());
    let put = state.parked_slices.get_mut("PUT /api").unwrap();
    put.rule_replay_pending = false;
    put.system_repair_accepted = true;
    assert!(!ready(&state, &scope));
    assert!(crate::rewrite::replay_admission::admitted(&state, &scope));
    assert!(crate::rewrite::worker::runtime::scopes(&state).is_empty());
}
use crate::rewrite::{self, RewriteAction, store::RewriteStore, worker};
use worker::tests::{configured_target, implementation_state_with_inventory};

#[test]
fn applied_rule_survives_restart_and_does_not_require_a_worker_handoff() {
    let target = configured_target();
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap()
        .activity = worker::model::RewriteWorkerActivity::Idle;
    let old_issue = state.active_issue.as_ref().unwrap().id.clone();
    request(&mut state);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let agent_handle = state.worker_bindings[&scope.binding_key()]
        .agent_handle
        .clone()
        .unwrap();
    worker::runtime::report(worker::runtime::RewriteWorkerReportOptions {
        target_root: target.path().into(),
        agent_handle,
        activity: worker::model::RewriteWorkerActivity::Idle,
        handoff_id: None,
        review_report: None,
    })
    .unwrap();
    let loaded = store.load().unwrap().unwrap();
    assert!(ready(&loaded, &scope));
    assert!(worker::runtime::scopes(&loaded).is_empty());
    assert_eq!(loaded.active_issue.as_ref().unwrap().id, old_issue);
    assert!(!loaded.e2e_current);
    assert!(!ready(
        &loaded,
        &RewriteWorkScope::Api {
            api: "/other".into()
        }
    ));
    let status = rewrite::status_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    assert!(!status.terminal_allowed);
    let details = rewrite::coordination::status_details(target.path(), &loaded).unwrap();
    assert!(!details.ready.contains_key("resume_worker"));
}

#[tokio::test]
async fn parked_rule_replay_is_selected_and_keeps_the_review_gate() {
    let target = configured_target();
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    let api = "GET /parked";
    let mut item = state.api_inventory[0].clone();
    item.api = api.into();
    item.source_route = Some("/parked".into());
    item.status = rewrite::model::RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(item);
    let mut slice = state.active_slice.clone();
    slice.api = api.into();
    slice.source_route = "/parked".into();
    slice.rule_replay_pending = true;
    state.parked_slices.insert(api.into(), slice);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let selected = rewrite::scheduling::idle_action(target.path(), &state).unwrap();
    let RewriteAction::AdvanceRequired {
        command,
        api: selected_api,
        ..
    } = selected
    else {
        panic!("schedule fresh Replay")
    };
    assert_eq!(
        selected_api.as_deref().unwrap(),
        crate::rewrite::api_selector::public_api(api)
    );
    assert_eq!(command.argv.last().unwrap(), "next");
    let result = rewrite::next_rewrite(crate::RewriteNextOptions {
        target_root: target.path().into(),
        api: Some(
            crate::rewrite::api_selector::public_api(api)
                .parse()
                .unwrap(),
        ),
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        result.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    assert!(state.parked_slices[api].rule_replay_pending);
}

#[tokio::test]
async fn parked_method_rule_replay_does_not_loop_on_the_other_method_after_skips() {
    let target = configured_target();
    std::fs::write(
        target.path().join(crate::config::regression::PATH),
        "auto_next: true\nskip: [/completed-a, /completed-b]\n",
    )
    .unwrap();
    let mut state = implementation_state_with_inventory(false);
    let api = "POST /api";
    let mut item = state.api_inventory[0].clone();
    item.api = api.into();
    item.status = rewrite::model::RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(item.clone());
    let mut sibling = state.active_slice.clone();
    sibling.api = api.into();
    sibling.active_issue.as_mut().unwrap().id = "post-issue".into();
    sibling.rule_replay_pending = true;
    state.parked_slices.insert(api.into(), sibling);
    for api in ["GET /completed-a", "GET /completed-b"] {
        let mut completed = item.clone();
        completed.api = api.into();
        completed.source_route = Some(crate::rewrite::api_selector::route(api).into());
        completed.status = rewrite::model::RewriteApiStatus::Complete;
        state.api_inventory.push(completed);
    }
    rewrite::regression_scope::apply(target.path(), &mut state).unwrap();
    worker::confirm_current_for_test(&mut state);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let status = rewrite::status_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        RewriteAction::AdvanceRequired { .. }
    ));
    let scoped = rewrite::status_rewrite_for_selector(
        crate::RewriteContext {
            target_root: target.path().into(),
        },
        &"/api".parse().unwrap(),
    )
    .unwrap();
    assert!(
        matches!(scoped.action, RewriteAction::SourceReviewRequired { .. }),
        "{:?}",
        scoped.action
    );
    let result = rewrite::next_rewrite(crate::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        result.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.api, api);
    assert!(saved.rule_replay_pending);
    assert!(!saved.parked_slices["GET /api"].rule_replay_pending);
    assert_eq!(
        saved.parked_slices["GET /api"].attempts.len(),
        state.attempts.len()
    );
    assert!(
        saved
            .api_inventory
            .iter()
            .filter(|item| item.api.starts_with("GET /completed-"))
            .all(|item| item.status == rewrite::model::RewriteApiStatus::Skipped)
    );
    assert_eq!(
        saved.worker_bindings["/api"].agent_handle,
        state.worker_bindings["/api"].agent_handle
    );
}

#[test]
fn finalized_replay_consumes_the_request_for_passed_and_dirty_results() {
    let target = configured_target();
    for passed in [false, true] {
        let mut state = implementation_state_with_inventory(false);
        request(&mut state);
        let result = crate::E2eApiRunResult {
            // A completed fresh Replay retains the actual executor identity.
            engine_fingerprint: Some(crate::build_info::ENGINE_FINGERPRINT.into()),
            run_key: "recording".into(),
            api: state.api.clone(),
            attempt: 2,
            status: if passed { "successful" } else { "failed" }.into(),
            passed,
            gates: crate::E2eVerificationGates {
                responses: crate::E2eResponseGate::Passed,
                replay: crate::E2eReplayGate::Complete,
                dependencies: if passed {
                    crate::E2eDependencyGate::Clean
                } else {
                    crate::E2eDependencyGate::Dirty
                },
            },
            diagnosis: crate::E2eDiagnosis {
                replay_finalized: None,
                egress_rejections: None,
                counts: crate::E2eDiagnosisCounts {
                    selected: 1,
                    executed: 1,
                    response_passed: 1,
                    response_nonpassing: 0,
                    response_incomplete: 0,
                },
                response_differences: crate::E2eResponseDifferenceDiagnosis {
                    total_differences: 0,
                    indexed_differences: 0,
                    omitted_differences: 0,
                    failure_clusters: vec![],
                    omitted_failure_clusters: 0,
                },
                representative: None,
                lifecycle_errors: vec![],
                execution_failures: Vec::new(),
            },
            progress: target.path().join("progress.yaml"),
            runtime_outputs: vec![],
        };
        rewrite::transition::from_e2e_result(
            target.path(),
            &mut state,
            &result,
            rewrite::transition::AttemptTransition::Append,
        )
        .unwrap();
        assert!(!state.rule_replay_pending);
        assert!(!any_ready(&state));
        assert_eq!(state.e2e_current, passed);
        assert_eq!(state.active_issue.is_none(), passed);
        assert_eq!(worker::runtime::scopes(&state).is_empty(), passed);
    }
}

#[test]
fn old_snapshots_do_not_create_a_replay_request() {
    let state = implementation_state_with_inventory(false);
    let mut value = serde_json::to_value(&state).unwrap();
    value.as_object_mut().unwrap().remove("rule_replay_pending");
    let loaded: RewriteState = serde_json::from_value(value).unwrap();
    assert!(!any_ready(&loaded));
}

mod header_apply;

#[test]
fn changed_process_policy_requests_one_replay_for_a_remaining_dependency_only_failure() {
    let target = configured_target();
    let mut state = implementation_state_with_inventory(false);
    state.active_issue.as_mut().unwrap().kind = rewrite::model::RewriteIssueKind::Dependency;
    state.attempts = vec![serde_json::from_value(serde_json::json!({
        "attempt": state.active_issue.as_ref().unwrap().attempt,
        "engine_fingerprint": crate::build_info::ENGINE_FINGERPRINT,
        "passed": false,
        "gates": {"responses":"passed", "replay":"complete", "dependencies":"dirty"},
        "counts": {"selected":1, "executed":1, "response_passed":1, "response_nonpassing":0, "response_incomplete":0}
    })).unwrap()];
    let api = state.api.clone();
    let scope = rewrite::api_selector::work_scope(&state, &api);
    after_process_rule(&mut state, &api, false);
    assert!(!pending(&state.active_slice));
    assert!(!rewrite::engine_retry::pending(&state, &state.active_slice));
    after_process_rule(&mut state, &api, true);
    assert!(ready(&state, &scope));
    assert!(!state.e2e_current);
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let mut restored = store.load().unwrap().unwrap();
    assert!(pending(&restored.active_slice));
    // A finished Replay clears this existing one-shot request (covered above).
    restored.rule_replay_pending = false;
    after_process_rule(&mut restored, &api, false);
    assert!(!pending(&restored.active_slice));
    restored.attempts[0].gates.responses = crate::E2eResponseGate::Nonpassing;
    after_process_rule(&mut restored, &api, true);
    assert!(!pending(&restored.active_slice));
    assert_eq!(restored.attempts.len(), 1);
    assert!(restored.active_issue.is_some());
}
