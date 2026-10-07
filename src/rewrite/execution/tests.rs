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
                api: Some("GET /api".into()),
                process_output: None,
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
