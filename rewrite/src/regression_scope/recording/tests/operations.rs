use super::*;
use std::path::PathBuf;

fn failed(root: &Path, recording: Option<&str>, finished: bool) -> PathBuf {
    let directory = crate::internal_runtime::root(root).join("rewrite/operations");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("current.json");
    fs::write(
        &path,
        serde_json::json!({
            "id":"operation-old-batch","pid":u32::MAX,
            "request":{"kind":"next","api":"GET /users/*","source_route":null},
            "recording_run_id":recording,"finished":finished,
            "error":finished.then_some("old recording directory no longer exists")
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        directory.join("operation-old-batch.log"),
        "original error\n",
    )
    .unwrap();
    path
}

fn original(root: &Path) -> RewriteState {
    record(root, A, &["GET /users/*"], &["/users/1"], "completed");
    policy(root, A, "only: [/users/*]\n");
    let mut state = workflow_test_support::test_state();
    super::super::super::apply(root, &mut state).unwrap();
    inventory::install(&mut state, vec!["GET /users/*".into()]).unwrap();
    state.phase = RewritePhase::ApiPending;
    RewriteStore::new(root).unwrap().save(&state).unwrap();
    state
}

#[test]
fn replaced_deleted_recording_retires_old_failures_and_keeps_new_failures() {
    for binding in [None, Some(A), Some(B)] {
        let root = target();
        original(root.path());
        let marker = failed(root.path(), binding, true);
        let before = fs::read(&marker).unwrap();
        record(
            root.path(),
            B,
            &["GET /orders/*"],
            &["/orders/2"],
            "completed",
        );
        policy(root.path(), B, "only: [/orders/*]\n");
        fs::remove_dir_all(artifacts::recording_run(root.path(), A)).unwrap();
        let report = rewrite::status_rewrite(RewriteContext {
            target_root: root.path().into(),
        })
        .unwrap();
        assert_eq!(
            matches!(report.action, RewriteAction::ExecutionFailed { .. }),
            binding == Some(B)
        );
        if binding == Some(B) {
            assert_eq!(fs::read(&marker).unwrap(), before);
        } else {
            assert!(!marker.exists());
            assert!(
                crate::retry_rewrite_operation(
                    RewriteContext {
                        target_root: root.path().into()
                    },
                    "operation-old-batch"
                )
                .is_err()
            );
        }
        assert_eq!(
            RewriteStore::new(root.path())
                .unwrap()
                .load()
                .unwrap()
                .unwrap()
                .recording_run_id,
            B
        );
        assert_eq!(
            fs::read_to_string(marker.parent().unwrap().join("operation-old-batch.log")).unwrap(),
            "original error\n"
        );
    }
}

#[test]
fn same_recording_invalid_replacement_and_unfinished_operations_keep_their_failure_state() {
    for state in ["unchanged", "incomplete", "unfinished"] {
        let root = target();
        let mut original = original(root.path());
        let marker = failed(root.path(), Some(A), state != "unfinished");
        let before = fs::read(&marker).unwrap();
        if state != "unchanged" {
            record(
                root.path(),
                B,
                &["GET /orders/*"],
                &["/orders/2"],
                if state == "incomplete" {
                    "running"
                } else {
                    "completed"
                },
            );
            policy(root.path(), B, "only: [/orders/*]\n");
        }
        let result = super::super::super::apply(root.path(), &mut original);
        if state == "incomplete" {
            assert!(result.is_err());
        } else {
            assert!(!result.unwrap());
        }
        assert_eq!(original.recording_run_id, A);
        assert_eq!(fs::read(marker).unwrap(), before);
    }
}
