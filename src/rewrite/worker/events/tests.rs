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
        api: feedback.api.clone(),
    };
    {
        let _feedback = lock(target.path()).unwrap();
        publish(target.path(), &feedback, &scope).unwrap();
    }
    let observed = store.load().unwrap().unwrap();
    assert_eq!(observed.worker_event_revision, 1);
    assert!(observed.worker_bindings.contains_key("GET /api"));
    // Simulates an in-flight Replay result that began before worker feedback.
    original.active_issue.as_mut().unwrap().attempt = 2;
    original.bump();
    store.save(&original).unwrap();
    let completed = store.load().unwrap().unwrap();
    assert_eq!(completed.active_issue.as_ref().unwrap().attempt, 2);
    assert!(completed.worker_bindings.contains_key("GET /api"));
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
                api: state.api.clone(),
            },
        )
        .unwrap();
    }
    state.workflow_id = "new-workflow".into();
    state.worker_bindings.clear();
    store.save(&state).unwrap();
    assert!(store.load().unwrap().unwrap().worker_bindings.is_empty());
}
