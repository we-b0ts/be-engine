use super::*;
use crate::rewrite::{api_batch, inventory, test_state};

fn stale(apis: &[&str]) -> RewriteState {
    let mut state = test_state();
    inventory::install(&mut state, apis.iter().map(|api| (*api).into()).collect()).unwrap();
    for item in &mut state.api_inventory {
        item.status = RewriteApiStatus::RevalidationPending;
        item.verified_target_fingerprint = Some("old".into());
    }
    state.phase = RewritePhase::SliceComplete;
    state.current_api_index = None;
    state
}

fn complete(state: &mut RewriteState, fingerprint: &str) {
    state.phase = RewritePhase::SliceComplete;
    state.e2e_current = true;
    state.target_fingerprint = Some(fingerprint.into());
    inventory::complete_current_and_advance(state).unwrap();
}

fn failure(api: &str) -> crate::E2eApiRunResult {
    serde_json::from_value(serde_json::json!({
        "run_key": "test-round", "api": api, "attempt": 1,
        "status": "failed", "passed": false,
        "gates": { "responses": "nonpassing", "replay": "complete", "dependencies": "clean" },
        "diagnosis": { "counts": { "selected": 1, "executed": 1,
            "response_passed": 0, "response_nonpassing": 1, "response_incomplete": 0 },
            "response_differences": { "total_differences": 0, "indexed_differences": 0,
                "omitted_differences": 0, "failure_clusters": [], "omitted_failure_clusters": 0 },
            "representative": null }, "progress": "unused.yaml"
    }))
    .unwrap()
}

#[test]
fn waits_for_every_implementation_and_acceptance_but_allows_gaps_and_skips() {
    let mut state = stale(&["GET /a", "GET /b"]);
    for status in [
        RewriteApiStatus::Pending,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::AwaitingRecordingRefresh,
        RewriteApiStatus::Active,
    ] {
        state.api_inventory[1].status = status;
        assert!(!begin(&mut state), "{status:?}");
        assert!(next(&state).is_none());
    }
    for status in [
        RewriteApiStatus::Complete,
        RewriteApiStatus::SystemRepairRequired,
        RewriteApiStatus::Skipped,
        RewriteApiStatus::RevalidationPending,
    ] {
        state.api_inventory[1].status = status;
        assert!(ready(&state), "{status:?}");
    }
    state.api_inventory[1].status = RewriteApiStatus::ImplementationRequired;
    assert!(inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).is_err());
    assert!(state.revalidation_round.is_none());
}

#[test]
fn fingerprint_changes_and_restart_do_not_repeat_a_finished_round_member() {
    let mut state = stale(&["GET /a", "GET /b", "GET /c"]);
    inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).unwrap();
    complete(&mut state, "v1");
    assert_eq!(state.api, "GET /b");
    inventory::defer_completed_for_target_change(&mut state, "v2").unwrap();
    inventory::defer_completed_for_target_change(&mut state, "v3").unwrap();
    let mut state: RewriteState =
        serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(next(&state), Some("GET /b"));
    assert!(!contains(&state, "GET /a"));
    assert!(inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).is_err());
    complete(&mut state, "v3");
    assert_eq!(state.api, "GET /c");
    complete(&mut state, "v3");
    // Only after the complete sweep may stale A join a new round.
    assert_eq!(state.api, "GET /a");
    assert!(contains(&state, "GET /a"));
    assert!(!contains(&state, "GET /b"));
    complete(&mut state, "v3");
    assert!(state.revalidation_round.is_none());
    assert!(next(&state).is_none());
    assert!(
        state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Complete)
    );
}

#[test]
fn multiple_failures_drain_the_sweep_then_all_repairs_must_be_accepted() {
    let target = crate::rewrite::worker::tests::configured_target();
    let mut state = stale(&["GET /a", "GET /b", "GET /c"]);
    let store = crate::rewrite::store::RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let report =
        crate::rewrite::review::check_pre_revalidation(crate::rewrite::RewriteReviewOptions {
            target_root: target.path().into(),
            worktree: Some(target.path().into()),
            scope: None,
            evidence: None,
            integration: false,
            handoff_id: None,
            hardcode_ai_verified: Vec::new(),
        })
        .unwrap();
    assert_eq!(report.status, crate::rewrite::review::ReviewStatus::Passed);
    crate::rewrite::review::accept(target.path().into(), report.report_path).unwrap();
    state = store.load().unwrap().unwrap();
    inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).unwrap();
    api_batch::apply_results(target.path(), &mut state, &[failure("GET /a")], None).unwrap();
    assert_eq!(next(&state), Some("GET /b"));
    assert!(!ready(&state));
    let action = crate::rewrite::action::for_state(target.path(), &state).action;
    assert!(
        matches!(action, crate::rewrite::RewriteAction::AdvanceRequired { api: Some(ref api), .. } if api == "/b")
    );
    inventory::activate_requested(&mut state, Some(&"GET /b".parse().unwrap())).unwrap();
    api_batch::apply_results(target.path(), &mut state, &[failure("GET /b")], None).unwrap();
    inventory::activate_requested(&mut state, Some(&"GET /c".parse().unwrap())).unwrap();
    complete(&mut state, "v1");
    assert!(state.revalidation_round.is_none());
    inventory::defer_completed_for_target_change(&mut state, "v2").unwrap();
    assert!(next(&state).is_none());
    // Accept A's repair; B still needs repair, so C remains deferred.
    assert_eq!(state.api, "GET /a");
    complete(&mut state, "v2");
    assert_eq!(state.api, "GET /b");
    assert!(state.revalidation_round.is_none());
    assert!(next(&state).is_none());
    complete(&mut state, "v2");
    assert_eq!(state.api, "GET /c");
    assert!(contains(&state, "GET /c"));
}

#[test]
fn old_snapshots_default_to_no_round_and_new_recordings_clear_membership() {
    let mut state = stale(&["GET /a"]);
    let mut value = serde_json::to_value(&state).unwrap();
    value.as_object_mut().unwrap().remove("revalidation_round");
    let restored: RewriteState = serde_json::from_value(value).unwrap();
    assert!(restored.revalidation_round.is_none());
    assert!(begin(&mut state));
    inventory::install(&mut state, vec!["GET /new".into()]).unwrap();
    assert!(state.revalidation_round.is_none());
}

#[test]
fn excluding_remaining_members_finishes_the_round() {
    let mut state = stale(&["GET /a", "GET /b"]);
    assert!(begin(&mut state));
    finish(&mut state, "GET /a");
    state.api_inventory[1].status = RewriteApiStatus::Skipped;
    reconcile_skips(&mut state);
    assert!(state.revalidation_round.is_none());
}

#[test]
fn active_round_member_does_not_hide_another_waiting_api() {
    let target = crate::rewrite::worker::tests::configured_target();
    let mut state = stale(&["GET /a", "GET /b", "GET /c"]);
    inventory::activate_requested(&mut state, Some(&"GET /a".parse().unwrap())).unwrap();
    complete(&mut state, "v1");
    // Exercise the round owner's projection; global admission independently
    // requires a current final review before selecting this Replay action.
    let action = crate::rewrite::scheduling::round_action(target.path(), &state).unwrap();
    let details = crate::rewrite::coordination::projected_details(
        target.path(),
        &state,
        &action,
        &action,
        false,
    );
    assert_eq!(details.ready.get("revalidate_api"), Some(&1));
    assert_eq!(details.waiting.get("final_revalidation"), Some(&1));
}
