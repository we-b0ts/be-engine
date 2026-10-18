use std::cell::RefCell;
use std::fs;
use std::path::Path;

use super::*;
use crate::rewrite::{
    action, api_batch, api_selector, inventory, model::*, store::RewriteStore, test_state, worker,
};
use worker::tests::{configured_target, implementation_state_with_inventory};

fn options(root: &Path) -> RewriteNextOptions {
    RewriteNextOptions {
        target_root: root.into(),
        api: None,
        source_route: None,
    }
}

fn enable(root: &Path) {
    fs::write(
        root.join(crate::config::regression::PATH),
        "auto_next: true\n",
    )
    .unwrap();
}

fn pending(root: &Path, apis: &[&str]) {
    enable(root);
    let mut state = test_state();
    inventory::install(&mut state, apis.iter().map(|api| (*api).into()).collect()).unwrap();
    RewriteStore::new(root).unwrap().save(&state).unwrap();
}

fn result(api: &str, passed: bool) -> crate::E2eApiRunResult {
    crate::E2eApiRunResult {
        engine_fingerprint: None,
        run_key: "test-replay".into(),
        api: api.into(),
        attempt: 1,
        status: if passed { "successful" } else { "failed" }.into(),
        passed,
        gates: crate::E2eVerificationGates {
            responses: if passed {
                crate::E2eResponseGate::Passed
            } else {
                crate::E2eResponseGate::Nonpassing
            },
            replay: crate::E2eReplayGate::Complete,
            dependencies: crate::E2eDependencyGate::Clean,
        },
        diagnosis: crate::E2eDiagnosis {
            egress_rejections: None,
            counts: crate::E2eDiagnosisCounts {
                selected: 1,
                executed: 1,
                response_passed: usize::from(passed),
                response_nonpassing: usize::from(!passed),
                response_incomplete: 0,
            },
            response_differences: crate::E2eResponseDifferenceDiagnosis {
                total_differences: 0,
                indexed_differences: 0,
                omitted_differences: 0,
                failure_clusters: Vec::new(),
                omitted_failure_clusters: 0,
            },
            representative: None,
            lifecycle_errors: Vec::new(),
        },
        progress: "unused-progress.yaml".into(),
        runtime_outputs: Vec::new(),
    }
}

// Exercise real inventory transitions, worker feedback merging and global scheduling,
// replacing only the Docker/traffic execution at the atomic step boundary.
fn replay(
    options: RewriteNextOptions,
    passed: bool,
    after: impl FnOnce(&mut RewriteState),
) -> AdvanceResult {
    let root = &options.target_root;
    let store = RewriteStore::new(root).unwrap();
    let _lock = store.lock().unwrap();
    let mut state = store.load().unwrap().unwrap();
    let selector = options.api.unwrap_or_else(|| {
        selected_api(&action::for_state(root, &state).action)
            .unwrap()
            .unwrap()
    });
    let api = api_selector::select(&state, &selector).unwrap();
    inventory::activate_requested(&mut state, Some(&api)).unwrap();
    api_batch::apply_results(root, &mut state, &[result(&api.to_string(), passed)], None).unwrap();
    after(&mut state);
    store.save(&state).unwrap();
    AdvanceResult {
        envelope: action::for_state(root, &state),
        replay_can_continue: passed || state.revalidation_round.is_some(),
    }
}

fn add_revalidation(state: &mut RewriteState, api: &str) {
    state.api_inventory.push(RewriteApiProgress {
        api: api.into(),
        source_route: Some(api_selector::route(api).into()),
        status: RewriteApiStatus::RevalidationPending,
        attempts: 1,
        e2e_current: false,
        verified_target_fingerprint: None,
    });
}

fn ready(state: &mut RewriteState) {
    let observation = state
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    observation.activity = worker::model::RewriteWorkerActivity::HandoffReady;
    observation.handoff_id = Some("retained-handoff".into());
}

fn admit_final(root: &Path) {
    let report =
        crate::rewrite::review::check_pre_revalidation(crate::rewrite::RewriteReviewOptions {
            target_root: root.into(),
            worktree: Some(root.into()),
            scope: None,
            evidence: None,
            integration: false,
            quality_check: Some("cargo-clippy".into()),
            handoff_id: None,
            hardcode_ai_verified: Vec::new(),
        })
        .unwrap();
    assert_eq!(report.status, crate::rewrite::review::ReviewStatus::Passed);
    crate::rewrite::review::accept(root.into(), report.report_path).unwrap();
}

#[tokio::test]
async fn single_mode_finishes_group_after_failure_and_returns_before_other_groups() {
    let target = configured_target();
    let root = target.path();
    let mut state = test_state();
    inventory::install(
        &mut state,
        vec!["GET /a".into(), "GET /other".into(), "GET /b".into()],
    )
    .unwrap();
    state.implementers = Some(crate::rewrite::implementer::ImplementerPool::new(16));
    // Store loads refresh the workflow snapshot from the project catalog, just
    // as a restarted coordinator does. Persist the analyzed groups themselves.
    let catalog = root.join(".traffic-e2e/local/repository-analysis/catalog.json");
    fs::create_dir_all(catalog.parent().unwrap()).unwrap();
    fs::write(
        catalog,
        serde_json::to_vec(&serde_json::json!({
            "api_groups": {"/a": "auth", "/b": "auth", "/other": "other"}
        }))
        .unwrap(),
    )
    .unwrap();
    RewriteStore::new(root).unwrap().save(&state).unwrap();
    let mut visited = Vec::new();
    run_steps(options(root), RewriteExecutionMode::Single, |options| {
        let store = RewriteStore::new(root).unwrap();
        let mut state = store.load().unwrap().unwrap();
        let selector = options
            .api
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "/a".parse().unwrap());
        let route = selector.to_string();
        crate::rewrite::group_replay::prepare(root, &mut state, &route).unwrap();
        store.save(&state).unwrap();
        visited.push(route.clone());
        let mut more = false;
        let mut result = replay(options, visited.len() != 1, |state| {
            more = crate::rewrite::group_replay::after_replay(root, state, &route).unwrap();
        });
        result.replay_can_continue |= more;
        std::future::ready(Ok(result))
    })
    .await
    .unwrap();
    assert_eq!(visited, ["/a", "/b"]);
    let state = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    assert!(state.group_replay.is_none());
    assert!(state.last_group_replay.as_ref().unwrap().complete);
    assert_eq!(state.api_inventory[1].attempts, 0);
}

#[test]
fn mode_uses_invocation_intent_instead_of_the_internal_selection() {
    let target = configured_target();
    let mut invocation = options(target.path());
    assert_eq!(mode(&invocation).unwrap(), RewriteExecutionMode::Single);
    let fingerprint = crate::rewrite::fingerprint::repository_fingerprint(target.path()).unwrap();
    enable(target.path());
    assert_eq!(
        crate::rewrite::fingerprint::repository_fingerprint(target.path()).unwrap(),
        fingerprint
    );
    assert_eq!(mode(&invocation).unwrap(), RewriteExecutionMode::AutoNext);
    invocation.api = Some("/api".parse().unwrap());
    assert_eq!(mode(&invocation).unwrap(), RewriteExecutionMode::Single);
    invocation.api = None;
    invocation.source_route = Some("/api".into());
    assert_eq!(mode(&invocation).unwrap(), RewriteExecutionMode::Single);
}

#[tokio::test]
async fn passing_pending_apis_continue_until_the_original_workflow_gate() {
    let target = configured_target();
    pending(target.path(), &["GET /a", "GET /b", "GET /c"]);
    let visited = RefCell::new(Vec::new());
    let output = run_steps(
        options(target.path()),
        RewriteExecutionMode::AutoNext,
        |options| {
            let result = replay(options, true, |state| {
                visited.borrow_mut().push(
                    state
                        .api_inventory
                        .iter()
                        .filter(|item| item.status == RewriteApiStatus::Complete)
                        .count(),
                );
            });
            std::future::ready(Ok(result))
        },
    )
    .await
    .unwrap();
    assert_eq!(*visited.borrow(), vec![1, 2, 3]);
    let expected = super::super::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(
        serde_json::to_value(&output.action).unwrap(),
        serde_json::to_value(&expected.action).unwrap()
    );
    assert!(!matches!(
        output.action,
        RewriteAction::AdvanceRequired {
            kind: RewriteAdvanceKind::Replay,
            ..
        }
    ));
    let latest = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(
        latest
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Complete && item.e2e_current)
    );
    assert!(!output.terminal_allowed);
}

#[tokio::test]
async fn failure_stops_before_the_next_pending_api() {
    let target = configured_target();
    pending(target.path(), &["GET /a", "GET /b", "GET /c"]);
    let mut calls = 0;
    let output = run_steps(
        options(target.path()),
        RewriteExecutionMode::AutoNext,
        |options| {
            calls += 1;
            std::future::ready(Ok(replay(options, calls != 2, |_| {})))
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 2);
    assert!(matches!(
        output.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    let latest = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(latest.api, "GET /b");
    assert_eq!(latest.api_inventory[2].attempts, 0);
}

#[tokio::test]
async fn explicit_api_executes_one_scope_even_when_auto_next_is_configured() {
    let target = configured_target();
    pending(target.path(), &["GET /a", "GET /b"]);
    let mut invocation = options(target.path());
    invocation.api = Some("/a".parse().unwrap());
    let mode = mode(&invocation).unwrap();
    let mut calls = 0;
    let output = run_steps(invocation, mode, |options| {
        calls += 1;
        std::future::ready(Ok(replay(options, true, |_| {})))
    })
    .await
    .unwrap();
    assert_eq!(calls, 1);
    assert!(
        matches!(output.action, RewriteAction::AdvanceRequired { api: Some(ref api), .. } if api == "/b")
    );
}

#[tokio::test]
async fn ready_handoff_keeps_first_pass_priority_then_takes_over() {
    let target = configured_target();
    enable(target.path());
    let mut state = implementation_state_with_inventory(true);
    worker::confirm_current_for_test(&mut state);
    ready(&mut state);
    let mut another = state.api_inventory[1].clone();
    another.api = "GET /third".into();
    another.source_route = Some("/third".into());
    state.api_inventory.push(another);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let mut calls = 0;
    let output = run_steps(
        options(target.path()),
        RewriteExecutionMode::AutoNext,
        |options| {
            calls += 1;
            std::future::ready(Ok(replay(options, true, |_| {})))
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 2);
    assert!(
        matches!(output.action, RewriteAction::IntegrationRequired { ref handoff_id, .. } if handoff_id == "retained-handoff")
    );
}

#[tokio::test]
async fn running_implementation_defers_revalidation_and_preserves_its_binding() {
    let target = configured_target();
    enable(target.path());
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    add_revalidation(&mut state, "GET /stale-a");
    add_revalidation(&mut state, "GET /stale-b");
    let binding = serde_json::to_value(&state.worker_bindings).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let output = next_rewrite(options(target.path())).await.unwrap();
    assert!(matches!(output.action, RewriteAction::WaitRequired { .. }));
    let saved = store.load().unwrap().unwrap();
    assert!(saved.revalidation_round.is_none());
    assert_eq!(
        serde_json::to_value(saved.worker_bindings).unwrap(),
        binding
    );
}

#[tokio::test]
async fn failed_members_and_a_ready_handoff_do_not_interrupt_the_round() {
    let target = configured_target();
    enable(target.path());
    let mut state = test_state();
    inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    state.api_inventory[0].status = RewriteApiStatus::RevalidationPending;
    state.phase = RewritePhase::SliceComplete;
    state.current_api_index = None;
    add_revalidation(&mut state, "GET /stale-a");
    add_revalidation(&mut state, "GET /stale-b");
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    admit_final(target.path());
    let mut calls = 0;
    let output = run_steps(
        options(target.path()),
        RewriteExecutionMode::AutoNext,
        |options| {
            calls += 1;
            std::future::ready(Ok(replay(options, calls == 3, |state| {
                if calls == 1 {
                    worker::confirm_current_for_test(state);
                    ready(state);
                }
            })))
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 3);
    assert!(
        matches!(output.action, RewriteAction::ImplementationRequired { ref worker, .. } if worker.work_scope.binding_key() == "/stale-a"),
        "{:?}",
        output.action
    );
    let saved = store.load().unwrap().unwrap();
    assert!(saved.revalidation_round.is_none());
    assert_eq!(
        saved.worker_bindings["/api"]
            .observation
            .as_ref()
            .unwrap()
            .activity,
        worker::model::RewriteWorkerActivity::HandoffReady
    );
    assert_eq!(
        saved.parked_slices["GET /stale-a"].phase,
        RewritePhase::ImplementationRequired
    );
}

#[tokio::test]
async fn changed_final_round_can_activate_the_integrated_failed_member() {
    for remaining_api in ["POST /other", "POST /api"] {
        let target = configured_target();
        let root = target.path();
        let mut state = test_state();
        inventory::install(&mut state, vec!["GET /api".into(), remaining_api.into()]).unwrap();
        for item in &mut state.api_inventory {
            item.status = RewriteApiStatus::RevalidationPending;
        }
        state.phase = RewritePhase::SliceComplete;
        state.current_api_index = None;
        let store = RewriteStore::new(root).unwrap();
        store.save(&state).unwrap();
        admit_final(root);
        replay(options(root), false, worker::integrate_current_for_test);
        let mut state = store.load().unwrap().unwrap();
        inventory::activate_requested(&mut state, Some(&remaining_api.parse().unwrap())).unwrap();
        store.save(&state).unwrap();
        fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();

        let mut projected = state.clone();
        assert!(crate::rewrite::review::pre_revalidation::reconcile(root, &mut projected).unwrap());
        assert_eq!(projected.phase, RewritePhase::SliceComplete);
        assert!(projected.current_api_index.is_none());
        inventory::activate_requested(&mut projected, Some(&"GET /api".parse().unwrap())).unwrap();
        assert_eq!(projected.api, "GET /api");

        let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
        let global = next_rewrite(options(root)).await.unwrap();
        assert!(matches!(
            global.action,
            RewriteAction::SourceReviewRequired { .. }
        ));
        assert_eq!(
            before,
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap()
        );

        let mut invocation = options(root);
        invocation.api = Some("/api".parse().unwrap());
        let result = crate::rewrite::advance::advance_rewrite(invocation)
            .await
            .unwrap();
        assert!(matches!(
            result.envelope.action,
            RewriteAction::SourceReviewRequired { .. }
        ));
        assert!(!result.replay_can_continue);
        let saved = store.load().unwrap().unwrap();
        assert_eq!(saved.api, "GET /api", "remaining method: {remaining_api}");
        assert!(saved.revalidation_round.is_none());
        assert_eq!(saved.attempts.len(), 1);
        assert_eq!(
            saved.api_inventory[1].status,
            RewriteApiStatus::RevalidationPending
        );
    }
}

#[tokio::test]
async fn a_new_dispatch_required_at_the_boundary_stops_continuation() {
    let target = configured_target();
    pending(target.path(), &["GET /a", "GET /b"]);
    let mut calls = 0;
    let output = run_steps(
        options(target.path()),
        RewriteExecutionMode::AutoNext,
        |options| {
            calls += 1;
            let result = replay(options, true, |state| {
                let issue = implementation_state_with_inventory(false);
                let mut item = issue.api_inventory[0].clone();
                item.status = RewriteApiStatus::ImplementationRequired;
                item.attempts = 1;
                state.api_inventory.push(item);
                state
                    .parked_slices
                    .insert(issue.api.clone(), issue.active_slice);
            });
            std::future::ready(Ok(result))
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 1);
    assert!(matches!(
        output.action,
        RewriteAction::ImplementationRequired { .. }
    ));
}

#[tokio::test]
async fn configuration_changes_and_disabling_auto_next_stop_at_the_boundary() {
    for change_configuration in [false, true] {
        let target = configured_target();
        pending(target.path(), &["GET /a", "GET /b"]);
        let mut calls = 0;
        let output = run_steps(
            options(target.path()),
            RewriteExecutionMode::AutoNext,
            |options| {
                calls += 1;
                let result = replay(options, true, |_| {});
                if change_configuration {
                    let path = target.path().join(".traffic-e2e/policy.yaml");
                    fs::write(
                        &path,
                        format!(
                            "{}\n# changed during Replay\n",
                            fs::read_to_string(&path).unwrap()
                        ),
                    )
                    .unwrap();
                } else {
                    fs::write(
                        target.path().join(crate::config::regression::PATH),
                        "auto_next: false\n",
                    )
                    .unwrap();
                }
                std::future::ready(Ok(result))
            },
        )
        .await
        .unwrap();
        assert_eq!(calls, 1);
        if change_configuration {
            assert!(matches!(
                output.action,
                RewriteAction::InputRequired {
                    reason: RewriteInputRequiredReason::ConfigurationCommitRequired,
                    ..
                }
            ));
        } else {
            assert!(matches!(
                output.action,
                RewriteAction::AdvanceRequired {
                    kind: RewriteAdvanceKind::Replay,
                    ..
                }
            ));
        }
    }
}

#[tokio::test]
async fn a_non_replay_or_stale_step_does_not_loop_on_an_advance_action() {
    let target = configured_target();
    pending(target.path(), &["GET /a", "GET /b"]);
    let mut calls = 0;
    let output = run_steps(
        options(target.path()),
        RewriteExecutionMode::AutoNext,
        |_| {
            calls += 1;
            let state = RewriteStore::new(target.path())
                .unwrap()
                .load()
                .unwrap()
                .unwrap();
            std::future::ready(Ok(AdvanceResult::without_replay(action::for_state(
                target.path(),
                &state,
            ))))
        },
    )
    .await
    .unwrap();
    assert_eq!(calls, 1);
    assert!(matches!(
        output.action,
        RewriteAction::AdvanceRequired {
            kind: RewriteAdvanceKind::Replay,
            ..
        }
    ));
}

#[test]
fn scope_selection_does_not_depend_on_public_command_arguments() {
    let target = configured_target();
    pending(target.path(), &["GET /a"]);
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    let action = action::for_state(target.path(), &state).action;
    assert_eq!(selected_api(&action).unwrap().unwrap().to_string(), "/a");
    let json = serde_json::to_value(action).unwrap();
    assert_eq!(json["details"]["operation"], "replay");
    assert_eq!(json["details"]["api"], "/a");
    assert!(
        !json["commands"]["advance"]["argv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg == "--api")
    );
}

#[tokio::test]
async fn a_plan_published_after_result_projection_stops_success_and_failure_continuation() {
    for passed in [true, false] {
        let target = configured_target();
        pending(target.path(), &["GET /first", "GET /second"]);
        let calls = RefCell::new(0);
        let envelope = run_steps(options(target.path()), RewriteExecutionMode::AutoNext, |invocation| {
            *calls.borrow_mut() += 1;
            let result = replay(invocation.clone(), passed, |_| {});
            // The coordinator already projected its result; an independent
            // planner publishes before the post-step scheduling boundary.
            let store = RewriteStore::new(&invocation.target_root).unwrap();
            let mut state = store.load().unwrap().unwrap();
            state.rule_plan = Some(serde_json::from_value(serde_json::json!({
                "id":"pending-plan", "issue_id":"old-issue", "kind":"unified", "json_pointer":"", "evidence_id":"old-evidence"
            })).unwrap());
            store.save(&state).unwrap();
            std::future::ready(Ok(result))
        }).await.unwrap();
        assert_eq!(*calls.borrow(), 1);
        let RewriteAction::PlanApplyRequired { command, .. } = envelope.action else {
            panic!("pending plan must be surfaced")
        };
        assert!(command.argv.contains(&"pending-plan".into()));
        assert!(
            command.argv.contains(&"recover".into()),
            "an expired plan is surfaced without applying it"
        );
        let state = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.phase == RewritePhase::ImplementationRequired, !passed);
        if !passed {
            assert!(state.active_issue.is_some());
            assert!(!state.attempts.last().unwrap().passed);
        }
        assert!(!envelope.terminal_allowed);
    }
}
