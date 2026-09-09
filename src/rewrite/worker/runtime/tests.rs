use super::*;
use crate::rewrite::{
    self, RewriteAction, RewriteContext, worker,
    worker::tests::{configured_target, implementation_state_with_inventory},
};

fn setup() -> (tempfile::TempDir, RewriteState, RewriteWorkScope) {
    let target = configured_target();
    let state = implementation_state_with_inventory(false);
    let scope = RewriteWorkScope::Api {
        api: state.api.clone(),
    };
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (target, state, scope)
}

fn options(
    target: &Path,
    state: &RewriteState,
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
                handoff_id: Some("commit-a".into()),
                hardcode_ai_verified: vec![],
            })
            .ok()
            .map(|r| r.report_path)
        }
        _ => None,
    };
    RewriteWorkerReportOptions {
        review_report,
        target_root: target.to_path_buf(),
        dispatch_id: worker::dispatch_id(state, scope),
        agent_handle: "actual-worker-a".into(),
        activity,
        handoff_id: matches!(
            activity,
            RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
        )
        .then(|| "commit-a".into()),
    }
}

fn confirm(target: &Path, state: &RewriteState, scope: &RewriteWorkScope) {
    worker::confirm(worker::RewriteWorkerConfirmOptions {
        worktree: Some(target.to_path_buf()),
        target_root: target.to_path_buf(),
        dispatch_id: worker::dispatch_id(state, scope),
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
    let RewriteAction::AdvanceRequired { command, .. } = integrated.action else {
        panic!("accepted quality receipt should advance verification")
    };
    assert_eq!(command.argv.last().unwrap(), "GET /api");
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
    let mut stale = options(target.path(), &state, &scope, RewriteWorkerActivity::Idle);
    stale.dispatch_id = "old-dispatch".into();
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
    assert_ne!(dispatch.dispatch_id, handoff.dispatch_id);
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
