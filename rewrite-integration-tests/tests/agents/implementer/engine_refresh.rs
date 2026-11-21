//! Keep the original pooled lease and accept its real handoff after an engine swap.
use super::*;

#[test]
fn engine_refresh_keeps_confirmed_pool_dispatch_and_accepts_its_original_handoff() {
    let (target, _) = setup();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let dispatch = confirm_group(root, "alpha");
    let task = dispatch
        .apis
        .iter()
        .find(|task| task.api == "/api")
        .unwrap();
    report(ImplementerReportOptions {
        target_root: root.into(),
        slot_id: 0,
        api: task.api.clone(),
        dispatch_id: task.dispatch_id.clone(),
        lease_generation: task.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Running,
    })
    .unwrap();
    let mut state = store.load().unwrap().unwrap();
    state.active_issue.as_mut().unwrap().kind = crate::model::RewriteIssueKind::TargetRuntime;
    let attempt = state.active_issue.as_ref().unwrap().attempt;
    state.attempts.push(serde_json::from_value(serde_json::json!({
        "engine_fingerprint":"engine-revision-v1:older", "attempt":attempt,
        "passed":false,"gates":{"responses":"incomplete","replay":"incomplete","dependencies":"unknown"},
        "counts":{"selected":1,"executed":0,"response_passed":0,"response_nonpassing":0,"response_incomplete":1}
    })).unwrap());
    store.save(&state).unwrap();
    let mut refreshed = store.load().unwrap().unwrap();
    let scope = crate::api_selector::work_scope(&refreshed, &refreshed.api);
    assert!(worker::runtime::scopes(&refreshed).contains(&scope));
    assert!(!traffic_rewrite::testing::reserve_engine_retry(
        &mut refreshed
    ));
    let lease = &refreshed.implementers.as_ref().unwrap().slots[&0].tasks["/api"];
    assert_eq!(lease.dispatch_id, task.dispatch_id);
    assert_eq!(lease.lease_generation, task.lease_generation);
    let delivered = delivery(root, &dispatch, "/api", "same-worker-delivery");
    handoff(ImplementerHandoffOptions {
        target_root: root.into(),
        slot_id: 0,
        agent_handle: "reused-handle".into(),
        deliveries: vec![delivered],
    })
    .unwrap();
    let accepted = store.load().unwrap().unwrap();
    assert_eq!(
        worker::runtime::coverage(&accepted, &scope),
        worker::model::RewriteWorkerCoverageState::IntegrationRequired
    );
    assert_eq!(accepted.attempts.len(), 1);
    assert!(accepted.engine_retry_fingerprints.is_empty());
}
