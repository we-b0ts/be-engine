//! A child may finish between the count and action projections of one status call.
use super::*;
use crate::model::{RewriteAction, RewritePhase};
use serde_json::json;
use std::fs;

#[test]
fn completion_after_execution_snapshot_keeps_counts_and_action_together() {
    let target = crate::worker::tests::configured_target();
    let mut state = crate::test_state();
    inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    state.phase = RewritePhase::ApiPending;
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let directory = crate::internal_runtime::root(target.path()).join("rewrite/operations");
    fs::create_dir_all(&directory).unwrap();
    let marker = directory.join("current.json");
    let mut operation = json!({
        "id":"operation-status-snapshot", "pid":unsafe { libc::getppid() },
        "request":{"kind":"next","api":"GET /api","source_route":null,"execution_mode":"single"},
        "recording_run_id":state.recording_run_id,"finished":false
    });
    fs::write(&marker, serde_json::to_vec(&operation).unwrap()).unwrap();
    let snapshot = crate::execution::status_action(target.path()).unwrap();
    assert!(matches!(snapshot, Some(RewriteAction::WaitRequired { .. })));

    // Deterministically publish the real marker transition after it was read,
    // before projecting either field. Both fields must use that one snapshot.
    operation["finished"] = json!(true);
    operation["error"] = json!("the canonical source route differs");
    let finished = serde_json::to_vec(&operation).unwrap();
    fs::write(&marker, &finished).unwrap();
    let prior = initialized_report(target.path(), state, None, snapshot.as_ref()).unwrap();
    assert_eq!(prior.pending, 1);
    assert!(matches!(prior.action, RewriteAction::WaitRequired { .. }));

    for _ in 0..2 {
        let current = status_rewrite(RewriteContext {
            target_root: target.path().into(),
        })
        .unwrap();
        assert_eq!(current.pending, 0);
        let RewriteAction::ExecutionFailed { operation_id, .. } = current.action else {
            panic!("a completed failed operation must require explicit retry");
        };
        assert_eq!(operation_id, "operation-status-snapshot");
        assert_eq!(fs::read(&marker).unwrap(), finished);
    }
}
