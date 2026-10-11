use super::*;
use crate::rewrite::{
    worker,
    worker::tests::{configured_target, implementation_state_with_inventory},
};

fn marker(target: &Path, pid: u32, finished: bool, error: Option<String>) {
    fs::create_dir_all(root(target)).unwrap();
    save(
        target,
        &Execution {
            id: "operation-test".into(),
            pid,
            request: Request::Next {
                execution_mode: RewriteExecutionMode::Single,
                api: Some("GET /api".into()),
                source_route: None,
            },
            finished,
            error,
        },
    )
    .unwrap();
}

#[test]
fn busy_summary_reports_the_current_traffic_phase_concisely() {
    let active = super::super::traffic_operation::TrafficOperationMarker {
        operation_id: "traffic-test".into(),
        kind: super::super::traffic_operation::TrafficOperationKind::Replay,
        api: Some("GET /api/teams".into()),
        started_at: "2026-09-22T00:00:00Z".into(),
        pid: std::process::id(),
    };
    assert_eq!(
        traffic_summary(&active, Some(crate::e2e_run::E2eActiveProgress::Building)),
        "building target for GET /api/teams"
    );
    assert_eq!(
        traffic_summary(
            &active,
            Some(crate::e2e_run::E2eActiveProgress::Replaying {
                completed: 932,
                total: 941,
            })
        ),
        "replaying GET /api/teams (932/941)"
    );
    assert_eq!(
        traffic_summary(&active, Some(crate::e2e_run::E2eActiveProgress::Finalizing)),
        "finalizing replay for GET /api/teams"
    );
}

#[test]
fn stopped_executor_requires_recovery_and_never_silently_retries() {
    let target = configured_target();
    marker(target.path(), u32::MAX, false, None);
    assert!(busy(target.path()).unwrap());
    assert!(matches!(
        status_action(target.path()).unwrap().unwrap(),
        RewriteAction::RecoveryRequired { .. }
    ));
    recover(target.path()).unwrap();
    assert!(!busy(target.path()).unwrap());
}

#[test]
fn failed_execution_waits_for_explicit_retry_while_workers_remain_dispatchable() {
    let target = configured_target();
    let state = implementation_state_with_inventory(false);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    marker(
        target.path(),
        u32::MAX,
        true,
        Some("test execution failed".into()),
    );
    let status = super::super::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(status.pending, 1);
    assert!(matches!(
        status.action,
        RewriteAction::ImplementationRequired { .. }
    ));
    let scope = super::super::RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    worker::confirm(worker::RewriteWorkerConfirmOptions {
        worktree: Some(target.path().to_path_buf()),
        target_root: target.path().into(),
        work_scope: scope.clone(),
        agent_handle: "runtime-worker".into(),
        agent_name: None,
    })
    .unwrap();
    worker::runtime::report(worker::runtime::RewriteWorkerReportOptions {
        review_report: None,
        target_root: target.path().into(),
        agent_handle: "runtime-worker".into(),
        activity: worker::model::RewriteWorkerActivity::Running,
        handoff_id: None,
    })
    .unwrap();
    let status = super::super::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(status.pending, 0);
    assert!(matches!(
        status.action,
        RewriteAction::ExecutionFailed { .. }
    ));
}

#[test]
fn legacy_next_markers_default_to_single_execution() {
    let request: Request = serde_json::from_value(serde_json::json!({
        "kind": "next", "api": "/api", "source_route": null,
    }))
    .unwrap();
    assert!(matches!(
        request,
        Request::Next {
            execution_mode: RewriteExecutionMode::Single,
            ..
        }
    ));
}

#[test]
fn retry_scope_tracks_the_current_auto_next_step_without_losing_the_mode() {
    let target = configured_target();
    marker(target.path(), std::process::id(), false, None);
    let mut current = load(target.path()).unwrap().unwrap();
    if let Request::Next { execution_mode, .. } = &mut current.request {
        *execution_mode = RewriteExecutionMode::AutoNext;
    }
    save(target.path(), &current).unwrap();
    update_next_scope(&RewriteNextOptions {
        target_root: target.path().into(),
        api: Some("/second".parse().unwrap()),
        source_route: None,
    })
    .unwrap();
    let updated = load(target.path()).unwrap().unwrap();
    assert_eq!(updated.id, current.id);
    assert!(matches!(updated.request, Request::Next {
        api: Some(ref api), execution_mode: RewriteExecutionMode::AutoNext, ..
    } if api == "/second"));
    assert!(busy(target.path()).unwrap());
    assert!(!super::super::coordination::resources_busy(target.path()).unwrap());
}

#[test]
fn external_status_reports_the_running_invocation_mode_even_between_apis() {
    for execution_mode in [RewriteExecutionMode::Single, RewriteExecutionMode::AutoNext] {
        let target = configured_target();
        // Configuration alone must not relabel an explicitly scoped operation.
        fs::write(
            target.path().join(crate::config::regression::PATH),
            "auto_next: true\n",
        )
        .unwrap();
        let mut state = implementation_state_with_inventory(false);
        state.phase = super::super::RewritePhase::ApiPending;
        state.active_issue = None;
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        marker(target.path(), child.id(), false, None);
        let mut current = load(target.path()).unwrap().unwrap();
        if let Request::Next {
            execution_mode: mode,
            ..
        } = &mut current.request
        {
            *mode = execution_mode;
        }
        save(target.path(), &current).unwrap();
        let report = super::super::status_rewrite(RewriteContext {
            target_root: target.path().into(),
        });
        let blocked = RewriteStore::new(target.path())
            .unwrap()
            .try_lock()
            .unwrap()
            .is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            blocked,
            "another process cannot advance between auto-next APIs"
        );
        let value = serde_json::to_value(report.unwrap()).unwrap();
        assert_eq!(value["action"]["kind"], "wait_required");
        assert_eq!(
            value["action"]["details"]["execution_mode"],
            serde_json::to_value(execution_mode).unwrap()
        );
        assert_eq!(
            value["action"]["summary"]
                .as_str()
                .unwrap()
                .contains("automatically advancing Replay"),
            execution_mode == RewriteExecutionMode::AutoNext
        );
        assert_eq!(value["action"]["commands"]["wait"]["argv"][3], "wait");
    }
}

#[test]
fn own_operation_marker_does_not_suppress_ready_integration_at_the_boundary() {
    let target = configured_target();
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    let observation = state
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    observation.activity = worker::model::RewriteWorkerActivity::HandoffReady;
    observation.handoff_id = Some("ready-handoff".into());
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    marker(target.path(), std::process::id(), false, None);
    let report = super::super::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        report.action,
        RewriteAction::IntegrationRequired { .. }
    ));
    let inventory = super::super::inventory_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(inventory.details.ready.get("integrate_handoff"), Some(&1));
}

#[test]
fn worker_actions_and_feedback_retain_auto_next_observability_while_replay_is_busy() {
    let target = configured_target();
    let state = implementation_state_with_inventory(false);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    marker(target.path(), child.id(), false, None);
    let mut current = load(target.path()).unwrap().unwrap();
    if let Request::Next { execution_mode, .. } = &mut current.request {
        *execution_mode = RewriteExecutionMode::AutoNext;
    }
    save(target.path(), &current).unwrap();
    let observed = (|| -> Result<_> {
        let status = super::super::status_rewrite(RewriteContext {
            target_root: target.path().into(),
        })?;
        let confirmation = worker::confirm(worker::RewriteWorkerConfirmOptions {
            target_root: target.path().into(),
            worktree: Some(target.path().into()),
            work_scope: super::super::RewriteWorkScope::Api { api: "/api".into() },
            agent_handle: "background-worker".into(),
            agent_name: None,
        })?;
        let feedback = worker::runtime::report(worker::runtime::RewriteWorkerReportOptions {
            target_root: target.path().into(),
            agent_handle: "background-worker".into(),
            activity: worker::model::RewriteWorkerActivity::Running,
            handoff_id: None,
            review_report: None,
        })?;
        Ok([
            serde_json::to_value(status)?,
            serde_json::to_value(confirmation)?,
            serde_json::to_value(feedback)?,
        ])
    })();
    let _ = child.kill();
    let _ = child.wait();
    let [status, confirmation, feedback] = observed.unwrap();
    for value in [&status, &confirmation, &feedback] {
        assert_eq!(value["action"]["details"]["execution_mode"], "auto_next");
        assert!(
            value["action"]["summary"]
                .as_str()
                .unwrap()
                .contains("automatically advancing Replay")
        );
    }
    assert_eq!(status["action"]["kind"], "implementation_required");
    assert_eq!(confirmation["action"]["kind"], "worker_status_required");
    assert_eq!(feedback["action"]["kind"], "wait_required");
}
