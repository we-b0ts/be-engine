//! Starting a fresh workflow may retire obsolete state, never execute it.
use super::*;

fn obsolete_snapshot(root: &Path) -> (String, Vec<u8>) {
    let mut old: serde_json::Value = serde_json::from_slice(&snapshot(root)).unwrap();
    old["version"] = 1.into();
    old.as_object_mut().unwrap().remove("dependency_review");
    old["recording_run_id"] = "retired-recording-with-no-evidence".into();
    old["worker_bindings"] = serde_json::json!({"obsolete": {"unsupported": true}});
    let id = old["workflow_id"].as_str().unwrap().to_owned();
    let payload = serde_json::to_vec_pretty(&old).unwrap();
    fs::write(
        crate::internal_runtime::root(root).join("rewrite/state.json"),
        &payload,
    )
    .unwrap();
    (id, payload)
}

#[test]
fn both_purposes_archive_obsolete_bytes_and_start_without_old_assignments() {
    for record_new_traffic in [false, true] {
        let target = fixture();
        let (previous_id, original) = obsolete_snapshot(target.path());
        let store = RewriteStore::new(target.path()).unwrap();
        assert!(store.load_snapshot().is_err());
        let report = begin(RewriteRegressionBeginOptions {
            record_new_traffic,
            ..options(target.path())
        })
        .unwrap();
        assert_eq!(
            report.previous_workflow_id.as_deref(),
            Some(previous_id.as_str())
        );
        assert_eq!(fs::read(report.archive.unwrap()).unwrap(), original);
        let state = store.load_snapshot().unwrap().unwrap();
        assert_eq!(state.version, rewrite::model::STATE_VERSION);
        assert_ne!(state.workflow_id, previous_id);
        assert!(state.worker_bindings.is_empty());
        assert!(state.dependency_review.receipts.is_empty());
        assert!(state.active_issue.is_none());
        assert_eq!(state.regression.unwrap().previous_workflow_id, previous_id);
        assert_eq!(
            state.recording_run_id,
            if record_new_traffic {
                ""
            } else {
                "20260802000000"
            }
        );
    }
}

#[test]
fn obsolete_state_survives_archive_and_branch_failures_byte_for_byte() {
    for block_archive in [false, true] {
        let target = fixture();
        let (_, original) = obsolete_snapshot(target.path());
        let block = if block_archive {
            crate::internal_runtime::root(target.path()).join("rewrite/history")
        } else {
            target.path().join(".git/HEAD.lock")
        };
        fs::write(block, "blocked").unwrap();
        let error = begin(options(target.path())).unwrap_err();
        assert!(
            !format!("{error:#}").contains("missing field `dependency_review`"),
            "obsolete state must reach the actual archive or branch failure"
        );
        if !block_archive {
            assert!(
                error
                    .to_string()
                    .contains("failed to enter the new purpose work branch")
            );
        }
        assert_eq!(snapshot(target.path()), original);
        assert_eq!(
            crate::purpose::base_branch(target.path()).unwrap(),
            Some("master".into())
        );
    }
}

#[test]
fn new_purpose_rejects_corrupt_current_and_unknown_future_state() {
    for version in [crate::model::STATE_VERSION, crate::model::STATE_VERSION + 1] {
        let target = fixture();
        obsolete_snapshot(target.path());
        let mut invalid: serde_json::Value =
            serde_json::from_slice(&snapshot(target.path())).unwrap();
        invalid["version"] = version.into();
        let original = serde_json::to_vec(&invalid).unwrap();
        fs::write(
            crate::internal_runtime::root(target.path()).join("rewrite/state.json"),
            &original,
        )
        .unwrap();
        for record_new_traffic in [false, true] {
            assert!(
                begin(RewriteRegressionBeginOptions {
                    record_new_traffic,
                    ..options(target.path())
                })
                .is_err()
            );
            assert_eq!(snapshot(target.path()), original);
            assert_eq!(
                crate::purpose::base_branch(target.path()).unwrap(),
                Some("master".into())
            );
        }
    }
}
