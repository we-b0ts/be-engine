use super::*;

fn waiting_final() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    inventory::install(&mut state, vec!["GET /a".into(), "POST /b".into()]).unwrap();
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::RevalidationPending;
        item.e2e_current = false;
        item.verified_target_fingerprint = Some("old-verified-candidate".into());
    }
    state.phase = RewritePhase::SliceComplete;
    state.current_api_index = None;
    inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).unwrap();
    state.pre_revalidation_review =
        Some(crate::rewrite::review::pre_revalidation::AcceptedReview {
            report_path: "old-final-review.json".into(),
            context: "old-policy".into(),
            receipt_identity: "receipt".into(),
            remaining: BTreeSet::from(["GET /a".into(), "POST /b".into()]),
        });
    state
}

#[test]
fn focused_request_retires_idle_final_admission_and_preserves_other_obligations() {
    let mut state = waiting_final();
    state
        .dependency_review
        .required_method_apis
        .insert("GET /required".into());
    let obligations = serde_json::to_value(&state.dependency_review).unwrap();
    assert!(available(&state));
    request(&mut state, &["GET /a".into()]).unwrap();
    assert!(state.revalidation_round.is_none());
    assert!(state.pre_revalidation_review.is_none());
    assert_eq!(state.phase, RewritePhase::ApiPending);
    assert_eq!(state.api, "GET /a");
    assert!(!state.e2e_current);
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Active);
    assert_eq!(
        state.api_inventory[1].status,
        RewriteApiStatus::RevalidationPending
    );
    assert_eq!(
        serde_json::to_value(&state.dependency_review).unwrap(),
        obligations
    );
    let target = super::super::tests::configured_target();
    assert!(
        crate::rewrite::review::pre_revalidation::required_action(target.path(), &state)
            .unwrap()
            .is_none()
    );
    assert!(crate::rewrite::dependency_review::batch_action(target.path(), &state).is_none());
}

#[test]
fn focused_request_cannot_discard_repairs_initial_work_or_replay_completion() {
    for status in [
        RewriteApiStatus::Pending,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::SystemRepairRequired,
    ] {
        let mut state = waiting_final();
        state.api_inventory[1].status = status;
        let before = serde_json::to_value(&state).unwrap();
        assert!(!available(&state));
        assert!(request(&mut state, &["GET /a".into()]).is_err());
        assert_eq!(serde_json::to_value(state).unwrap(), before);
    }
    let mut state = waiting_final();
    state.api_inventory[0].verified_target_fingerprint = None;
    assert!(request(&mut state, &["GET /a".into()]).is_err());
}

#[test]
fn public_focused_request_recovers_queued_final_api_through_normal_replay_action() {
    let target = super::super::tests::configured_target();
    let state = waiting_final();
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let report = super::super::request(RewriteRevalidationRequestOptions {
        target_root: target.path().into(),
        apis: vec!["/a".parse().unwrap()],
        reason: "Redis policy changed; replay existing complete cases".into(),
        focused: true,
    })
    .unwrap();
    assert!(report.focused);
    assert!(
        matches!(report.next.action, RewriteAction::AdvanceRequired { .. }),
        "{:?}",
        report.next.action
    );
    let saved = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(saved.revalidation_round.is_none());
    assert!(!saved.e2e_current);
    assert!(saved.attempts.is_empty());
}
