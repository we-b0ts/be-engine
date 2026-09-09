//! Upgrades retain old failed operation records without restarting quality jobs.
use super::*;
use crate::rewrite::review::{ReviewStatus, RewriteReviewOptions};
use crate::rewrite::worker;
use crate::rewrite::worker::tests::{configured_target, implementation_state_with_inventory};

const OPERATION_ID: &str = "operation-legacy-quality-failure";

fn legacy_failure(counter: &Path) -> tempfile::TempDir {
    let target = configured_target();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::rewrite::test_support::managed_test_recorder(),
        Some(serde_json::json!([{
            "name": "rust-clippy",
            "argv": ["sh", "-c", "printf x >> \"$1\"", "quality-test", counter]
        }])),
    );
    for arguments in [
        vec!["add", ".traffic-e2e/project.yaml"],
        vec!["commit", "-qm", "configured delivery checks"],
        vec!["switch", "-qc", "coordinator"],
    ] {
        crate::rewrite::source_diff::git_text(target.path(), &arguments).unwrap();
    }
    let mut state = implementation_state_with_inventory(false);
    // An old engine accepted this worker's integration before running clippy;
    // there is deliberately no complete delivery review receipt in the fixture.
    worker::integrate_current_for_test(&mut state);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    fs::create_dir_all(root(target.path())).unwrap();
    fs::write(
        path(target.path()),
        serde_json::to_vec(&serde_json::json!({
            "id": OPERATION_ID,
            "pid": u32::MAX,
            "request": {
                "kind": "target_quality",
                "api": "GET /api",
                "gate_id": "quality-gate-from-old-engine",
                "hardcode_ai_verified": []
            },
            "finished": true,
            "error": "target quality gate \"rust-clippy\" failed with exit status: 101"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root(target.path()).join(format!("{OPERATION_ID}.log")),
        "original compiler diagnostic\n",
    )
    .unwrap();
    target
}

fn retry_without_relaunch(target: &Path) -> RewriteActionEnvelope {
    let store = RewriteStore::new(target).unwrap();
    let before_state = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let mut before_execution = serde_json::to_value(load(target).unwrap().unwrap()).unwrap();
    assert!(matches!(
        status_action(target).unwrap(),
        Some(RewriteAction::ExecutionFailed { .. })
    ));
    let before_files = operation_files(target);
    let result = retry(
        RewriteContext {
            target_root: target.into(),
        },
        OPERATION_ID,
    )
    .unwrap();
    // Retry retires only the old error. A new PID/ID/request/log would expose an
    // accidental detached launch, even if its command eventually also failed.
    before_execution.as_object_mut().unwrap().remove("error");
    assert_eq!(
        serde_json::to_value(load(target).unwrap().unwrap()).unwrap(),
        before_execution
    );
    assert_eq!(operation_files(target), before_files);
    assert_eq!(
        fs::read_to_string(root(target).join(format!("{OPERATION_ID}.log"))).unwrap(),
        "original compiler diagnostic\n"
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before_state
    );
    assert!(status_action(target).unwrap().is_none());
    assert!(!busy(target).unwrap());
    result
}

fn operation_files(target: &Path) -> std::collections::BTreeSet<std::ffi::OsString> {
    fs::read_dir(root(target))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

#[test]
fn old_failed_quality_retry_routes_missing_receipt_to_integrator_without_checks() {
    let directory = tempfile::tempdir().unwrap();
    let counter = directory.path().join("quality-invocations");
    let target = legacy_failure(&counter);
    let result = retry_without_relaunch(target.path());
    assert!(matches!(
        result.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    assert!(!result.terminal_allowed);
    let status = crate::rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        RewriteAction::SourceReviewRequired { .. }
    ));
    assert!(status.pending > 0, "receipt repair must remain schedulable");
    assert!(!counter.exists());
}

#[test]
fn old_failed_quality_retry_admits_current_receipt_without_reexecuting_checks() {
    let directory = tempfile::tempdir().unwrap();
    let counter = directory.path().join("quality-invocations");
    let target = legacy_failure(&counter);
    let report = crate::rewrite::review::check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: true,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    crate::rewrite::review::accept(target.path().into(), report.report_path).unwrap();
    assert_eq!(fs::read_to_string(&counter).unwrap(), "x");
    let result = retry_without_relaunch(target.path());
    assert!(matches!(
        result.action,
        RewriteAction::AdvanceRequired { .. }
    ));
    let status = crate::rewrite::status_rewrite(RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(matches!(
        status.action,
        RewriteAction::AdvanceRequired { .. }
    ));
    assert_eq!(fs::read_to_string(&counter).unwrap(), "x");
}
