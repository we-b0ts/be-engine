use super::*;
use crate::rewrite::{
    store::RewriteStore, worker, worker::tests::implementation_state_with_inventory,
};

#[test]
fn feedback_is_visible_during_transition_and_survives_an_old_snapshot_save() {
    let target = tempfile::tempdir().unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut original = implementation_state_with_inventory(false);
    store.save(&original).unwrap();
    let _transition = store.lock().unwrap();
    let mut feedback = store.load().unwrap().unwrap();
    worker::confirm_current_for_test(&mut feedback);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&feedback.api).to_string(),
    };
    {
        let _feedback = lock(target.path()).unwrap();
        publish(target.path(), &feedback, &scope).unwrap();
    }
    let observed = store.load().unwrap().unwrap();
    assert_eq!(observed.worker_event_revision, 1);
    assert!(observed.worker_bindings.contains_key("/api"));
    // Simulates an in-flight Replay result that began before worker feedback.
    original.active_issue.as_mut().unwrap().attempt = 2;
    original.bump();
    store.save(&original).unwrap();
    let completed = store.load().unwrap().unwrap();
    assert_eq!(completed.active_issue.as_ref().unwrap().attempt, 2);
    assert!(completed.worker_bindings.contains_key("/api"));
    assert_eq!(completed.worker_event_revision, 1);
    let revision = completed.revision;
    assert_eq!(store.load().unwrap().unwrap().revision, revision);
}

#[test]
fn old_workflow_feedback_does_not_bind_a_new_workflow() {
    let target = tempfile::tempdir().unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    {
        let _guard = lock(target.path()).unwrap();
        publish(
            target.path(),
            &state,
            &RewriteWorkScope::Api {
                api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
            },
        )
        .unwrap();
    }
    state.workflow_id = "new-workflow".into();
    state.worker_bindings.clear();
    store.save(&state).unwrap();
    assert!(store.load().unwrap().unwrap().worker_bindings.is_empty());
}

#[test]
fn method_snapshot_and_route_feedback_merge_by_revision_without_rewriting_files() {
    let target = tempfile::tempdir().unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    let previous = state.worker_bindings.remove("/api").unwrap();
    state
        .worker_bindings
        .insert("GET /api".into(), previous.clone());
    let mut latest = previous.clone();
    latest.confirmed_dispatch_id = "route-dispatch".into();
    latest.rework_generation += 1;
    let updates = WorkerUpdates {
        implementers: None,
        workflow_id: state.workflow_id.clone(),
        revision: 2,
        bindings: BTreeMap::from([
            (
                "GET /api".into(),
                BindingUpdate {
                    revision: 1,
                    binding: previous,
                },
            ),
            (
                "/api".into(),
                BindingUpdate {
                    revision: 2,
                    binding: latest.clone(),
                },
            ),
        ]),
    };
    fs::create_dir_all(root(target.path())).unwrap();
    let snapshot_path = root(target.path()).join("state.json");
    let feedback_path = root(target.path()).join("worker-updates.json");
    let snapshot_bytes = serde_json::to_vec(&state).unwrap();
    let feedback_bytes = serde_json::to_vec(&updates).unwrap();
    fs::write(&snapshot_path, &snapshot_bytes).unwrap();
    fs::write(&feedback_path, &feedback_bytes).unwrap();
    for _ in 0..2 {
        let loaded = store.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.worker_bindings.len(), 1);
        assert_eq!(loaded.worker_event_revision, 2);
        assert_eq!(
            serde_json::to_value(&loaded.worker_bindings["/api"]).unwrap(),
            serde_json::to_value(&latest).unwrap()
        );
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_bytes);
        assert_eq!(fs::read(&feedback_path).unwrap(), feedback_bytes);
    }
    // A late verifier save must fold in the same newest callback and persist
    // only the route key, keeping the accepted task and its ownership metadata.
    store.save(&state).unwrap();
    let loaded = store.load_snapshot().unwrap().unwrap();
    assert_eq!(loaded.worker_bindings.len(), 1);
    assert_eq!(
        serde_json::to_value(&loaded.worker_bindings["/api"]).unwrap(),
        serde_json::to_value(&latest).unwrap()
    );
}

#[test]
fn duplicate_aliases_cannot_silently_choose_between_distinct_workers() {
    let target = tempfile::tempdir().unwrap();
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    let binding = state.worker_bindings["/api"].clone();
    let mut conflicting = binding.clone();
    conflicting.agent_handle_fingerprint = "another-worker".into();
    state
        .worker_bindings
        .insert("PUT /api".into(), conflicting.clone());
    assert!(
        overlay(target.path(), &mut state)
            .unwrap_err()
            .to_string()
            .contains("multiple workers own API /api")
    );
    let updates = WorkerUpdates {
        implementers: None,
        workflow_id: state.workflow_id.clone(),
        revision: 1,
        bindings: BTreeMap::from([
            (
                "GET /api".into(),
                BindingUpdate {
                    revision: 1,
                    binding,
                },
            ),
            (
                "/api".into(),
                BindingUpdate {
                    revision: 1,
                    binding: conflicting,
                },
            ),
        ]),
    };
    fs::create_dir_all(root(target.path())).unwrap();
    fs::write(
        root(target.path()).join("worker-updates.json"),
        serde_json::to_vec(&updates).unwrap(),
    )
    .unwrap();
    assert!(
        normalize_updates(&mut load(target.path()).unwrap())
            .unwrap_err()
            .to_string()
            .contains("multiple workers own API /api")
    );
    // Conflicting callbacks from a different workflow are historical and
    // must not block or resurrect workers in the current workflow.
    let mut new_workflow = implementation_state_with_inventory(false);
    new_workflow.workflow_id = "new-workflow".into();
    overlay(target.path(), &mut new_workflow).unwrap();
    assert!(new_workflow.worker_bindings.is_empty());
}
