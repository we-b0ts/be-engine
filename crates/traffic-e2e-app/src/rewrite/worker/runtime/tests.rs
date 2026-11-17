use super::*;
use crate::rewrite::{
    self, RewriteAction, RewriteContext, worker,
    worker::tests::{configured_target, implementation_state_with_inventory},
};

fn setup() -> (tempfile::TempDir, RewriteState, RewriteWorkScope) {
    let target = configured_target();
    let state = implementation_state_with_inventory(false);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (target, state, scope)
}

fn options(
    target: &Path,
    _state: &RewriteState,
    scope: &RewriteWorkScope,
    activity: RewriteWorkerActivity,
) -> RewriteWorkerReportOptions {
    let review_report = match activity {
        RewriteWorkerActivity::HandoffReady => Some(crate::rewrite::review::tests::worker_report(
            target,
            scope.clone(),
        )),
        RewriteWorkerActivity::Integrated => {
            crate::rewrite::review::check(crate::rewrite::RewriteReviewOptions {
                target_root: target.into(),
                worktree: Some(target.into()),
                scope: Some(scope.clone()),
                evidence: None,
                integration: true,
                quality_check: None,
                handoff_id: Some("commit-a".into()),
                hardcode_ai_verified: vec![],
            })
            .ok()
            .map(|r| r.report_path)
        }
        _ => None,
    };
    RewriteWorkerReportOptions {
        delivery_commit: None,
        review_report,
        target_root: target.to_path_buf(),
        agent_handle: "actual-worker-a".into(),
        activity,
        handoff_id: matches!(
            activity,
            RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
        )
        .then(|| "commit-a".into()),
    }
}

fn confirm(target: &Path, _state: &RewriteState, scope: &RewriteWorkScope) {
    worker::confirm(worker::RewriteWorkerConfirmOptions {
        worktree: Some(target.to_path_buf()),
        target_root: target.to_path_buf(),
        work_scope: scope.clone(),
        agent_handle: "actual-worker-a".into(),
        agent_name: None,
    })
    .unwrap();
}

#[test]
fn handoff_wakes_idle_coordinator_and_only_its_api_becomes_ready_for_acceptance() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let confirmation = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(confirmation.pending, 1);
    assert!(matches!(
        confirmation.action,
        RewriteAction::WorkerStatusRequired { .. }
    ));
    report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Running,
    ))
    .unwrap();
    let running = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(running.pending, 1);
    assert!(matches!(running.action, RewriteAction::WaitRequired { .. }));
    let handoff = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    let response = report(handoff.clone()).unwrap();
    assert_eq!(response.pending, 1);
    assert!(matches!(
        response.action,
        RewriteAction::IntegrationRequired { .. }
    ));
    let store = RewriteStore::new(target.path()).unwrap();
    let revision = store.load().unwrap().unwrap().revision;
    report(handoff.clone()).unwrap();
    assert_eq!(store.load().unwrap().unwrap().revision, revision);
    let integrated = report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Integrated,
    ))
    .unwrap();
    assert_eq!(integrated.pending, 1);
    let RewriteAction::AdvanceRequired { command, api, .. } = integrated.action else {
        panic!("accepted quality receipt should advance verification")
    };
    assert_eq!(api.as_deref(), Some("/api"));
    assert_eq!(command.argv.last().unwrap(), "next");
    report(handoff).unwrap();
    assert!(acceptance_ready(&store.load().unwrap().unwrap(), &scope));
}

#[test]
fn idle_worker_becomes_resume_required_and_running_report_cannot_fake_a_resume() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let stopped = report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Idle,
    ))
    .unwrap();
    assert_eq!(stopped.pending, 1);
    assert!(matches!(
        stopped.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    assert!(
        report(options(
            target.path(),
            &state,
            &scope,
            RewriteWorkerActivity::Running
        ))
        .is_err()
    );
    // Resume has a new dispatch identity. Late completion from the old turn
    // cannot mark the resumed worker's current work ready for integration.
    assert!(
        report(options(
            target.path(),
            &state,
            &scope,
            RewriteWorkerActivity::HandoffReady
        ))
        .is_err()
    );
    let latest = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    confirm(target.path(), &latest, &scope);
    report(options(
        target.path(),
        &latest,
        &scope,
        RewriteWorkerActivity::Queued,
    ))
    .unwrap();
    assert_eq!(
        rewrite::status_rewrite(RewriteContext {
            target_root: target.path().into()
        })
        .unwrap()
        .pending,
        1
    );
}

#[test]
fn confirmation_does_not_refresh_or_invent_an_activity_report() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let store = RewriteStore::new(target.path()).unwrap();
    assert!(observation(&store.load().unwrap().unwrap(), &scope).is_none());
    report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Running,
    ))
    .unwrap();
    let mut reported = store.load().unwrap().unwrap();
    let value = reported
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    value.observed_at = "2000-01-01T00:00:00Z".into();
    store.save(&reported).unwrap();
    confirm(target.path(), &reported, &scope);
    let after = store.load().unwrap().unwrap();
    assert_eq!(
        observation(&after, &scope).unwrap().observed_at,
        "2000-01-01T00:00:00Z"
    );
    assert_eq!(
        coverage(&after, &scope),
        RewriteWorkerCoverageState::StatusRequired
    );
}

#[test]
fn legacy_automatic_running_requires_an_explicit_coordinator_report() {
    let (target, mut state, scope) = setup();
    worker::confirm_current_for_test(&mut state);
    state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap()
        .coordinator_reported = false;
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    assert_eq!(
        coverage(&state, &scope),
        RewriteWorkerCoverageState::StatusRequired
    );
}

#[test]
fn running_and_queued_reports_have_a_refreshable_sixty_minute_expiry() {
    for activity in [
        RewriteWorkerActivity::Running,
        RewriteWorkerActivity::Queued,
    ] {
        let (target, state, scope) = setup();
        confirm(target.path(), &state, &scope);
        report(options(target.path(), &state, &scope, activity)).unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = store.load().unwrap().unwrap();
        for (age_minutes, expired) in [(15, false), (59, false), (60, true), (61, true)] {
            let observation = state
                .worker_bindings
                .get_mut(&scope.binding_key())
                .unwrap()
                .observation
                .as_mut()
                .unwrap();
            observation.activity = activity;
            observation.observed_at =
                (Utc::now() - chrono::Duration::minutes(age_minutes)).to_rfc3339();
            store.save(&state).unwrap();

            let status = rewrite::status_rewrite(RewriteContext {
                target_root: target.path().into(),
            })
            .unwrap();
            assert_eq!(
                status.pending, 1,
                "{activity:?} report at {age_minutes} minutes"
            );
            if expired {
                assert!(matches!(
                    status.action,
                    RewriteAction::WorkerStatusRequired { .. }
                ));
            } else {
                assert!(matches!(status.action, RewriteAction::WaitRequired { .. }));
            }
        }

        let previous = observation(&state, &scope).unwrap().observed_at.clone();
        let refreshed = report(options(target.path(), &state, &scope, activity)).unwrap();
        assert!(matches!(
            refreshed.action,
            RewriteAction::WaitRequired { .. }
        ));
        let state = store.load().unwrap().unwrap();
        assert_ne!(observation(&state, &scope).unwrap().observed_at, previous);
        assert_eq!(
            coverage(&state, &scope),
            RewriteWorkerCoverageState::Running
        );
    }
}

#[test]
fn handed_off_workers_do_not_expire_while_waiting_for_integration_or_verification() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let store = RewriteStore::new(target.path()).unwrap();
    for activity in [
        RewriteWorkerActivity::HandoffReady,
        RewriteWorkerActivity::Integrated,
    ] {
        report(options(target.path(), &state, &scope, activity)).unwrap();
        let mut waiting = store.load().unwrap().unwrap();
        waiting
            .worker_bindings
            .get_mut(&scope.binding_key())
            .unwrap()
            .observation
            .as_mut()
            .unwrap()
            .observed_at = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        store.save(&waiting).unwrap();

        let status = rewrite::status_rewrite(RewriteContext {
            target_root: target.path().into(),
        })
        .unwrap();
        match activity {
            RewriteWorkerActivity::HandoffReady => assert!(matches!(
                status.action,
                RewriteAction::IntegrationRequired { .. }
            )),
            RewriteWorkerActivity::Integrated => assert!(matches!(
                status.action,
                RewriteAction::AdvanceRequired { .. }
            )),
            _ => unreachable!(),
        }
    }
}

#[test]
fn historical_or_expired_confirmation_requires_runtime_observation_not_automatic_duplicate_dispatch()
 {
    let (target, mut state, scope) = setup();
    worker::confirm_current_for_test(&mut state);
    state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation = None;
    assert_eq!(
        coverage(&state, &scope),
        RewriteWorkerCoverageState::StatusRequired
    );
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let status = rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(status.pending, 1);
    assert!(matches!(
        status.action,
        RewriteAction::WorkerStatusRequired { .. }
    ));
    record_running_for_test(&mut state, &scope);
    state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap()
        .observed_at = "2020-01-01T00:00:00Z".into();
    assert_eq!(
        coverage(&state, &scope),
        RewriteWorkerCoverageState::StatusRequired
    );
}

#[test]
fn current_transition_does_not_block_feedback_but_integration_waits() {
    let (target, state, scope) = setup();
    let store = RewriteStore::new(target.path()).unwrap();
    let lock = store.lock().unwrap();
    confirm(target.path(), &state, &scope);
    let handoff = report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    ))
    .unwrap();
    assert_eq!(handoff.pending, 1);
    assert!(
        report(options(
            target.path(),
            &state,
            &scope,
            RewriteWorkerActivity::Integrated
        ))
        .is_err()
    );
    drop(lock);
    assert_eq!(
        rewrite::status_rewrite(RewriteContext {
            target_root: target.path().into()
        })
        .unwrap()
        .pending,
        1
    );
}

#[test]
fn rejected_handle_stale_dispatch_and_unreceived_handoff_do_not_change_state() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let store = RewriteStore::new(target.path()).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let mut wrong = options(target.path(), &state, &scope, RewriteWorkerActivity::Idle);
    wrong.agent_handle = "unrelated-worker".into();
    assert!(report(wrong).is_err());
    let stale = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    let path = stale.review_report.as_ref().unwrap();
    let mut review: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    review["dispatch_id"] = "old-dispatch".into();
    std::fs::write(path, serde_json::to_vec(&review).unwrap()).unwrap();
    assert!(report(stale).is_err());
    assert!(
        report(options(
            target.path(),
            &state,
            &scope,
            RewriteWorkerActivity::Integrated
        ))
        .is_err()
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
}

#[test]
fn integration_conflict_resumes_same_worker_and_rejects_old_handoff() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let handoff = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    report(handoff.clone()).unwrap();
    let mut rework = handoff.clone();
    rework.activity = RewriteWorkerActivity::ReworkRequired;
    let response = report(rework).unwrap();
    assert_eq!(response.pending, 1);
    let RewriteAction::ImplementationRequired {
        worker: dispatch, ..
    } = response.action
    else {
        panic!("conflicting handoff must return to its worker")
    };
    assert_eq!(
        dispatch.state,
        crate::rewrite::RewriteWorkerDispatchState::ResumeRequired
    );
    assert_ne!(dispatch.dispatch_id, worker::dispatch_id(&state, &scope));
    assert!(report(handoff).is_err());
    let latest = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    confirm(target.path(), &latest, &scope);
    report(options(
        target.path(),
        &latest,
        &scope,
        RewriteWorkerActivity::Running,
    ))
    .unwrap();
    let latest = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        coverage(&latest, &scope),
        RewriteWorkerCoverageState::Running
    );
    assert_eq!(
        latest.worker_bindings[&scope.binding_key()].rework_generation,
        1
    );
}

#[test]
fn reviewed_rework_resumes_its_worker_before_an_optional_changed_engine_retry() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let handoff = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    report(handoff.clone()).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut current = store.load().unwrap().unwrap();
    current.active_issue.as_mut().unwrap().kind =
        crate::rewrite::model::RewriteIssueKind::TargetRuntime;
    current.attempts.push(serde_json::from_value(serde_json::json!({
        "engine_fingerprint":"engine-revision-v1:older", "attempt":1,"passed":false,
        "gates":{"responses":"incomplete","replay":"incomplete","dependencies":"unknown"},
        "counts":{"selected":1,"executed":0,"response_passed":0,"response_nonpassing":0,"response_incomplete":1}
    })).unwrap());
    store.save(&current).unwrap();
    let mut rework = handoff.clone();
    rework.activity = RewriteWorkerActivity::ReworkRequired;
    let response = report(rework).unwrap();
    let RewriteAction::ImplementationRequired {
        worker: dispatch, ..
    } = response.action
    else {
        panic!(
            "reviewed rework must resume instead of spending a known-failing Replay: {:?}",
            response.action
        )
    };
    assert_eq!(
        dispatch.state,
        crate::rewrite::RewriteWorkerDispatchState::ResumeRequired
    );
    let mut latest = store.load().unwrap().unwrap();
    assert_eq!(latest.attempts.len(), 1);
    assert!(latest.engine_retry_fingerprints.is_empty());
    assert!(!crate::rewrite::engine_retry::reserve(&mut latest, None));
    assert!(
        report(handoff).is_err(),
        "the old accepted handoff stays immutable"
    );
}

#[test]
fn resumed_review_preserves_original_report_and_rejects_late_deliveries() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let old = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    let old_path = old.review_report.as_ref().unwrap();
    let original = std::fs::read(old_path).unwrap();
    report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Idle,
    ))
    .unwrap();
    confirm(target.path(), &state, &scope);
    let new = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    assert_ne!(new.review_report.as_ref(), Some(old_path));
    assert_eq!(std::fs::read(old_path).unwrap(), original);
    report(new.clone()).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    for activity in [
        RewriteWorkerActivity::HandoffReady,
        RewriteWorkerActivity::Integrated,
        RewriteWorkerActivity::ReworkRequired,
    ] {
        let mut late = old.clone();
        late.activity = activity;
        assert!(
            report(late)
                .unwrap_err()
                .to_string()
                .contains("stale dispatch")
        );
    }
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    // The new report still supports idempotent callbacks and genuine rework.
    report(new.clone()).unwrap();
    let mut rework = new;
    rework.activity = RewriteWorkerActivity::ReworkRequired;
    report(rework).unwrap();
    assert_eq!(
        coverage(&store.load().unwrap().unwrap(), &scope),
        RewriteWorkerCoverageState::ResumeRequired
    );
}

#[test]
fn handle_report_backfills_persisted_identity_and_returns_an_executable_handle_command() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let store = RewriteStore::new(target.path()).unwrap();
    let mut legacy = store.load().unwrap().unwrap();
    legacy
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .agent_handle = None;
    store.save(&legacy).unwrap();
    report(options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Running,
    ))
    .unwrap();
    let persisted = store.load().unwrap().unwrap();
    let view = worker::dispatch_view(&persisted, scope.clone(), None);
    assert_eq!(view.agent_handle.as_deref(), Some("actual-worker-a"));
    let command = report_command(target.path(), view.agent_handle.as_deref(), false);
    assert!(
        command
            .argv
            .windows(2)
            .any(|args| args == ["--agent-handle", "actual-worker-a"])
    );
    assert!(!command.argv.contains(&view.dispatch_id));
    assert!(
        !command
            .required_env_names
            .contains(&worker::AGENT_HANDLE_ENV.to_string())
    );
    // The handle no longer addresses reportable work once the API has completed.
    let mut completed = persisted;
    completed.phase = RewritePhase::SliceComplete;
    store.save(&completed).unwrap();
    assert!(
        report(options(
            target.path(),
            &state,
            &scope,
            RewriteWorkerActivity::Running
        ))
        .is_err()
    );
}

#[test]
fn replacement_handle_cannot_admit_the_previous_workers_report() {
    let (target, state, scope) = setup();
    confirm(target.path(), &state, &scope);
    let old = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::HandoffReady,
    );
    let transfer = worker::RewriteWorkerTransferOptions {
        target_root: target.path().into(),
        previous_agent_handle: "actual-worker-a".into(),
        agent_handle: "replacement-worker".into(),
        agent_name: None,
        reason: "runtime no longer has the original worker".into(),
        caller_approved: false,
        runtime_query: Some(worker::RewriteWorkerMissingQuery {
            api_or_command: "runtime.get_agent".into(),
            queried_at: "2026-09-12T12:00:00+08:00".into(),
        }),
    };
    let store = RewriteStore::new(target.path()).unwrap();
    let assignment = serde_json::to_value(
        &store.load().unwrap().unwrap().worker_bindings["/api"].review_assignment,
    )
    .unwrap();
    worker::transfer(transfer.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(
            &store.load().unwrap().unwrap().worker_bindings["/api"].review_assignment,
        )
        .unwrap(),
        assignment
    );
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    assert!(worker::transfer(transfer).is_err());
    assert!(report(old.clone()).is_err());
    let mut mislabeled = old;
    mislabeled.agent_handle = "replacement-worker".into();
    assert!(
        report(mislabeled)
            .unwrap_err()
            .to_string()
            .contains("stale dispatch")
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    let mut live = options(
        target.path(),
        &state,
        &scope,
        RewriteWorkerActivity::Running,
    );
    live.agent_handle = "replacement-worker".into();
    report(live).unwrap();
    assert_eq!(
        coverage(&store.load().unwrap().unwrap(), &scope),
        RewriteWorkerCoverageState::Running
    );
}
