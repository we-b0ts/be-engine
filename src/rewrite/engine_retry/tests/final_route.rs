//! Final-route fallback admission, scheduling and durable per-method reservation.
use super::*;
use crate::rewrite::engine_retry::pending;
use serde_json::json;

fn response_state() -> RewriteState {
    let mut state = runtime_state(Some("engine-revision-v1:older"));
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    state.attempts[0].gates = crate::E2eVerificationGates {
        responses: crate::E2eResponseGate::Nonpassing,
        replay: crate::E2eReplayGate::Complete,
        dependencies: crate::E2eDependencyGate::Dirty,
    };
    state.attempts[0].counts.executed = 1;
    state.attempts[0].counts.response_nonpassing = 1;
    state.attempts[0].counts.response_incomplete = 0;
    state
}

fn item(state: &mut RewriteState, api: &str, status: RewriteApiStatus) {
    let mut item = state.api_inventory[0].clone();
    item.api = api.into();
    item.source_route = Some(api_selector::public_api(api).into());
    item.status = status;
    state.api_inventory.push(item);
}

#[test]
fn final_route_response_retry_preserves_revalidation_and_failure_across_restart() {
    let target = worker::tests::configured_target();
    let mut state = response_state();
    item(&mut state, "GET /complete", RewriteApiStatus::Complete);
    item(
        &mut state,
        "GET /revalidate",
        RewriteApiStatus::RevalidationPending,
    );
    item(&mut state, "GET /skip", RewriteApiStatus::Skipped);
    // Store reload reapplies the source-controlled scope, so persist the skip
    // as a real caller would rather than inventing an excluded ledger item.
    std::fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "skip:\n  - /skip\n",
    )
    .unwrap();
    let issue = serde_json::to_value(&state.active_issue).unwrap();
    let inventory = serde_json::to_value(&state.api_inventory).unwrap();
    assert!(pending(&state, &state.active_slice));
    assert!(any_pending(&state));
    assert!(worker::runtime::scopes(&state).is_empty());
    let scope = api_selector::work_scope(&state, &state.api);
    assert!(replay_admission::admitted(&state, &scope));
    assert!(matches!(
        action::state_action(target.path(), &state),
        RewriteAction::AdvanceRequired { .. }
    ));
    assert!(reserve(&mut state, None));
    assert!(!pending(&state, &state.active_slice));
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let mut restored = store.load().unwrap().unwrap();
    assert!(clear_running(&mut restored));
    assert!(!reserve(&mut restored, None));
    assert_eq!(restored.attempts.len(), 1);
    assert_eq!(serde_json::to_value(&restored.active_issue).unwrap(), issue);
    assert_eq!(
        serde_json::to_value(&restored.api_inventory).unwrap(),
        inventory
    );
    assert!(
        restored
            .engine_retry_fingerprints
            .contains(crate::build_info::ENGINE_FINGERPRINT)
    );
    assert!(eligible_failure(
        &restored.active_slice,
        "engine-revision-v1:later",
        true
    ));
}

#[test]
fn admitted_source_receipt_keeps_changed_engine_retry_guidance_visible() {
    use crate::rewrite::review::{self, RewriteReviewOptions};

    let target = worker::tests::configured_target();
    let root = target.path();
    rewrite::source_diff::git_text(root, &["switch", "-qc", "coordinator"]).unwrap();
    let state = response_state();
    let store = RewriteStore::new(root).unwrap();
    store.save(&state).unwrap();
    let report = review::check(RewriteReviewOptions {
        target_root: root.into(),
        worktree: None,
        scope: None,
        evidence: None,
        integration: false,
        quality_check: None,
        handoff_id: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    review::accept(root.into(), report.report_path).unwrap();
    let before = serde_json::to_value(store.load().unwrap()).unwrap();

    let status = rewrite::status_rewrite(crate::RewriteContext {
        target_root: root.into(),
    })
    .unwrap();
    match status.action {
        RewriteAction::AdvanceRequired { summary, kind, .. } => {
            assert_eq!(kind, crate::rewrite::model::RewriteAdvanceKind::Replay);
            assert!(summary.contains("engine build changed"), "{summary}");
        }
        action => panic!("expected changed-engine Replay guidance, got {action:?}"),
    }
    assert!(!status.terminal_allowed);
    assert_eq!(serde_json::to_value(store.load().unwrap()).unwrap(), before);
    assert!(worker::runtime::scopes(&store.load().unwrap().unwrap()).is_empty());
}

#[test]
fn another_unfinished_route_blocks_only_the_fallback() {
    for status in [
        RewriteApiStatus::Pending,
        RewriteApiStatus::Active,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::SystemRepairRequired,
        RewriteApiStatus::AwaitingRecordingRefresh,
    ] {
        let mut state = response_state();
        item(&mut state, "GET /other", status);
        assert!(!pending(&state, &state.active_slice), "{status:?}");
        assert!(!reserve(&mut state, None));
        assert!(!worker::runtime::scopes(&state).is_empty());
        // Existing runtime and dependency-only permits do not acquire this condition.
        state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::TargetRuntime;
        assert!(pending(&state, &state.active_slice));
        let mut state = dependency_state(Some("engine-revision-v1:older"));
        item(&mut state, "GET /other", status);
        assert!(pending(&state, &state.active_slice));
    }
}

#[test]
fn one_route_with_two_failed_methods_reserves_each_permit_before_execution() {
    let mut state = response_state();
    sibling(&mut state, "PUT /api", RewriteIssueKind::Response);
    item(
        &mut state,
        "GET /revalidate",
        RewriteApiStatus::RevalidationPending,
    );
    let scope = api_selector::work_scope(&state, &state.api);
    assert!(replay_admission::admitted(&state, &scope));
    assert!(worker::runtime::scopes(&state).is_empty());
    let mut prepared = rewrite::api_batch::PreparedRoute {
        apis: vec![state.api.clone(), "PUT /api".into()],
        slices: std::iter::once((state.api.clone(), state.active_slice.clone()))
            .chain(state.parked_slices.clone())
            .collect(),
    };
    assert!(reserve(&mut state, Some(&mut prepared)));
    assert!(state.engine_retry_running);
    assert!(state.parked_slices["PUT /api"].engine_retry_running);
    assert!(
        prepared
            .slices
            .values()
            .all(|slice| !pending(&state, slice))
    );
    assert!(!reserve(&mut state, Some(&mut prepared)));
    clear_running(&mut state);
    assert!(!replay_admission::admitted(&state, &scope));
}

#[test]
fn one_method_without_a_fresh_permit_keeps_the_route_worker_outstanding() {
    let mut state = response_state();
    sibling(&mut state, "PUT /api", RewriteIssueKind::Response);
    state.parked_slices.get_mut("PUT /api").unwrap().attempts[0].engine_fingerprint =
        Some(crate::build_info::ENGINE_FINGERPRINT.into());
    let scope = api_selector::work_scope(&state, &state.api);
    assert!(!replay_admission::admitted(&state, &scope));
    assert_eq!(worker::runtime::scopes(&state), vec![scope]);
    assert!(replay_admission::admitted(
        &state,
        &RewriteWorkScope::Api {
            api: state.api.clone()
        }
    ));
}

#[test]
fn parked_final_failure_is_scheduled_without_dispatching_another_implementer() {
    let target = worker::tests::configured_target();
    let mut state = response_state();
    sibling(&mut state, "GET /parked", RewriteIssueKind::Response);
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    state.phase = RewritePhase::SliceComplete;
    state.active_issue = None;
    assert!(any_pending(&state));
    assert!(worker::runtime::scopes(&state).is_empty());
    assert!(matches!(
        rewrite::scheduling::idle_action(target.path(), &state),
        Some(RewriteAction::AdvanceRequired { .. })
    ));
    assert!(pending(&state, &state.parked_slices["GET /parked"]));
}

#[test]
fn fallback_requires_a_real_failed_attempt_on_a_known_different_engine() {
    for mode in 0..8 {
        let mut state = response_state();
        match mode {
            0 => {
                state.attempts[0].engine_fingerprint =
                    Some(crate::build_info::ENGINE_FINGERPRINT.into())
            }
            1 => state.attempts[0].engine_fingerprint = None,
            2 => state.attempts[0].passed = true,
            3 => state.attempts.clear(),
            4 => state.active_issue.as_mut().unwrap().attempt = 2,
            5 => state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::TargetQuality,
            6 => state.api_inventory[0].status = RewriteApiStatus::Skipped,
            7 => state.attempts[0].counts.selected = 0,
            _ => unreachable!(),
        }
        assert!(!pending(&state, &state.active_slice), "mode={mode}");
        assert!(!reserve(&mut state, None), "mode={mode}");
    }
    let mut state = response_state();
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Replay;
    state.attempts[0].gates.replay = crate::E2eReplayGate::Incomplete;
    assert!(pending(&state, &state.active_slice));
}

#[tokio::test]
async fn fallback_status_is_read_only_and_retry_needs_case_inputs_without_review() {
    let target = worker::tests::configured_target();
    let state = response_state();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let before = serde_json::to_value(store.load().unwrap()).unwrap();
    for _ in 0..2 {
        let status = rewrite::status_rewrite(crate::RewriteContext {
            target_root: target.path().into(),
        })
        .unwrap();
        assert!(matches!(
            status.action,
            RewriteAction::AdvanceRequired { .. }
        ));
        assert!(!status.terminal_allowed);
        assert_eq!(serde_json::to_value(store.load().unwrap()).unwrap(), before);
    }
    let next = rewrite::next_rewrite(crate::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .await
    .unwrap_err();
    assert!(next.to_string().contains("case source"), "{next:#}");
    let restored = store.load().unwrap().unwrap();
    assert!(pending(&restored, &restored.active_slice));
    assert!(restored.engine_retry_fingerprints.is_empty());
    assert_eq!(
        serde_json::to_value(&restored.active_issue).unwrap(),
        json!(state.active_issue)
    );
}
