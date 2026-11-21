//! Storage-only migration preserves workflow semantics and original bytes on failure.
use super::*;

fn fixture() -> (tempfile::TempDir, Vec<u8>) {
    let target = tempfile::tempdir().unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    fs::create_dir_all(store.snapshots.root()).unwrap();
    let state = crate::test_state();
    let mut value = serde_json::to_value(state).unwrap();
    value["dependency_review"]["decision_history"] = json!({
        "format": "dependency-decision-history/v1",
        "groups": [{
            "template": {
                "owner": {
                    "kind": "process", "process_epoch": uuid::Uuid::from_u128(1),
                    "source_task": "test-subscriber", "invocation": null
                },
                "proof_id": "proof-history", "proof_revision": 2,
                "proof": {
                    "source_revision": "source-revision",
                    "source_locations": ["source/subscriber.rs:10"],
                    "call_chain": "The independent source subscriber receives notifications.",
                    "exclusive_scope": "One source process subscription"
                },
                "rule_bindings": {"task-test-subscriber": "rule-fingerprint"}
            },
            "exchange_ids": (1..=4096).map(uuid::Uuid::from_u128).collect::<Vec<_>>()
        }]
    });
    let original = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(store.snapshots.state_path(), &original).unwrap();
    (target, original)
}

fn context(target: &Path) -> RewriteContext {
    RewriteContext {
        target_root: target.into(),
    }
}

fn without_history(bytes: &[u8]) -> Value {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    value["dependency_review"]
        .as_object_mut()
        .unwrap()
        .remove("decision_history");
    value
}

#[test]
fn compaction_preserves_workflow_and_reuses_the_exact_migrated_snapshot() {
    let (target, original) = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let value: Value = serde_json::from_slice(&original).unwrap();
    // A storage migration must not adopt pending worker or rule-plan feedback.
    fs::write(
        store.snapshots.root().join("worker-updates.json"),
        serde_json::to_vec(&json!({
            "workflow_id":value["workflow_id"],"revision":9,"bindings":{}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::create_dir_all(store.snapshots.root().join("rule-plans")).unwrap();
    fs::write(
        store.snapshots.root().join("rule-plans/events.json"),
        serde_json::to_vec(&json!({
            "workflow_id":value["workflow_id"],"revision":11,"plans":{}
        }))
        .unwrap(),
    )
    .unwrap();
    let compact = compact_rewrite_decision_history(context(target.path())).unwrap();
    assert_eq!(compact["changed"], true);
    assert_eq!(compact["history_groups"], 1);
    assert_eq!(compact["history_occurrences"], 4096);
    assert_eq!(compact["inline_history"], false);
    let after = fs::read(store.snapshots.state_path()).unwrap();
    assert_eq!(without_history(&after), without_history(&original));
    assert!(after.len() * 5 < original.len());
    assert_eq!(
        fs::read(compact["backup"].as_str().unwrap()).unwrap(),
        original
    );
    let verified = verify_rewrite_decision_history(context(target.path())).unwrap();
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["revision"], compact["revision"]);
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), after);

    let repeated = compact_rewrite_decision_history(context(target.path())).unwrap();
    assert_eq!(repeated["changed"], false);
    assert!(repeated["backup"].is_null());
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), after);
}

#[test]
fn archive_failure_retains_original_state_in_compaction_and_ordinary_save() {
    let (target, original) = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let (_, state) = read_raw(&store).unwrap();
    fs::write(
        store.snapshots.root().join("decision-history"),
        b"block archive directory",
    )
    .unwrap();
    assert!(compact_rewrite_decision_history(context(target.path())).is_err());
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), original);
    assert!(store.save(&state).is_err());
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), original);
}

#[test]
fn compaction_preserves_omitted_defaults_and_forward_compatible_fields() {
    let (target, original) = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    let fields = value.as_object_mut().unwrap();
    for name in [
        "recording_apis",
        "current_api_index",
        "worker_event_revision",
        "api_catalog_initialized",
        "api_catalog",
    ] {
        fields.remove(name);
    }
    fields.insert(
        "future_storage_annotation".into(),
        json!({"mode":"strict","values":[1,null,{"keep":true}]}),
    );
    let original = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(store.snapshots.state_path(), &original).unwrap();
    assert!(read_raw(&store).is_ok());
    assert!(compact_rewrite_decision_history(context(target.path())).is_ok());
    let after = fs::read(store.snapshots.state_path()).unwrap();
    assert_eq!(without_history(&after), without_history(&original));
    assert!(verify_rewrite_decision_history(context(target.path())).is_ok());
}

#[test]
fn backup_failure_does_not_publish_a_replacement_state() {
    let (target, original) = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    fs::write(
        store.snapshots.root().join("history"),
        b"block backup directory",
    )
    .unwrap();
    assert!(compact_rewrite_decision_history(context(target.path())).is_err());
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), original);
}

#[test]
fn failed_state_commit_keeps_original_history_and_retry_reuses_durable_bodies() {
    let (target, original) = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let (_, state) = read_raw(&store).unwrap();
    let temporary = store.snapshots.root().join(format!(
        ".state.json.tmp.{}.{}",
        std::process::id(),
        state.revision
    ));
    fs::write(&temporary, b"block state publication").unwrap();
    assert!(compact_rewrite_decision_history(context(target.path())).is_err());
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), original);
    assert_eq!(
        fs::read_dir(store.snapshots.root().join("decision-history"))
            .unwrap()
            .count(),
        1
    );
    fs::remove_file(temporary).unwrap();
    let compact = compact_rewrite_decision_history(context(target.path())).unwrap();
    assert_eq!(compact["history_occurrences"], 4096);
    assert_eq!(
        fs::read_dir(store.snapshots.root().join("decision-history"))
            .unwrap()
            .count(),
        1
    );
    assert!(verify_rewrite_decision_history(context(target.path())).is_ok());
}

#[test]
fn compaction_rejects_live_and_stale_coordinator_and_traffic_owners() {
    let (target, original) = fixture();
    let store = RewriteStore::new(target.path()).unwrap();
    let lock = store.lock().unwrap();
    assert!(compact_rewrite_decision_history(context(target.path())).is_err());
    drop(lock);
    fs::write(store.snapshots.root().join("lock"), u32::MAX.to_string()).unwrap();
    assert!(compact_rewrite_decision_history(context(target.path())).is_err());
    fs::remove_file(store.snapshots.root().join("lock")).unwrap();

    for pid in [std::process::id(), u32::MAX] {
        fs::write(
            store.snapshots.root().join("traffic-operation.json"),
            serde_json::to_vec(&json!({
                "operation_id":"traffic-history-test", "kind":"replay",
                "pid":pid,"started_at":"2026-11-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(compact_rewrite_decision_history(context(target.path())).is_err());
        fs::remove_file(store.snapshots.root().join("traffic-operation.json")).unwrap();
    }
    let operations = store.snapshots.root().join("operations");
    fs::create_dir_all(&operations).unwrap();
    for pid in [std::process::id(), u32::MAX] {
        fs::write(
            operations.join("current.json"),
            serde_json::to_vec(&json!({
                "id":"operation-history-test", "pid":pid,"finished":false,
                "request":{"kind":"next","api":null,"source_route":null,"execution_mode":"single"}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(compact_rewrite_decision_history(context(target.path())).is_err());
    }
    assert_eq!(fs::read(store.snapshots.state_path()).unwrap(), original);
}

#[test]
fn inherited_history_remains_verifiable_after_the_workflow_changes() {
    let (target, _) = fixture();
    compact_rewrite_decision_history(context(target.path())).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let (_, mut state) = read_raw(&store).unwrap();
    let previous = super::super::replacement::PreviousWorkflow::Current(Box::new(state.clone()));
    state.workflow_id = "rewrite-inherited-history".into();
    store.save(&state).unwrap();
    let verified = verify_rewrite_decision_history(context(target.path())).unwrap();
    assert_eq!(verified["workflow_id"], "rewrite-inherited-history");
    assert_eq!(verified["history_occurrences"], 4096);
    let feedback = worker::events::lock(target.path()).unwrap();
    store.restore_snapshot(Some(&previous), &feedback).unwrap();
    assert!(verify_rewrite_decision_history(context(target.path())).is_ok());
}

#[test]
fn missing_archive_is_an_explicit_audit_error_without_loading_history_on_status() {
    let (target, _) = fixture();
    compact_rewrite_decision_history(context(target.path())).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    fs::remove_dir_all(store.snapshots.root().join("decision-history")).unwrap();
    assert!(store.load_snapshot().unwrap().is_some());
    assert!(verify_rewrite_decision_history(context(target.path())).is_err());
}
