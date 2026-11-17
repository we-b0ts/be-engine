//! Evidence type errors provide a usable next command without renewing traffic.
use super::*;

#[test]
fn current_overview_redirects_to_detail_planning_without_replay_or_redispatch() {
    let fixture = Fixture::new();
    fixture.confirm();
    let scope = RewriteWorkScope::Api { api: "/api".into() };
    let overview = query_rewrite_evidence_for_scope(fixture.context(), &scope).unwrap();
    let detail = overview
        .queries
        .iter()
        .find(|query| query.query_id.ends_with("unified-rule-candidates"))
        .unwrap();
    let policy = fs::read(fixture.policy()).unwrap();
    let state = fixture.state();
    assert_eq!(
        inventory::api_for_ownership_evidence_id(fixture.root(), &state, &overview.evidence_id)
            .unwrap(),
        state.api
    );
    let before = serde_json::to_value(state).unwrap();
    let error = plan_rewrite_unified_rule(
        fixture.context(),
        RewriteUnifiedRulePlanOptions {
            file: fixture.proposal.clone(),
            evidence_id: overview.evidence_id,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("current issue overview is not planning evidence"),
        "{error}"
    );
    assert!(error.contains(&detail.query_id));
    assert!(error.contains("No new Replay or dispatch"));
    assert!(!error.contains("stale"));
    assert_eq!(serde_json::to_value(fixture.state()).unwrap(), before);
    assert_eq!(fs::read(fixture.policy()).unwrap(), policy);

    // Follow the actual returned query, retaining the same issue and lease.
    let evidence = query_rewrite_evidence(fixture.context(), &detail.query_id).unwrap();
    let plan = plan_rewrite_unified_rule(
        fixture.context(),
        RewriteUnifiedRulePlanOptions {
            file: fixture.proposal.clone(),
            evidence_id: evidence.evidence_id,
        },
    )
    .unwrap();
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    let state = fixture.state();
    assert_eq!(
        state.active_issue.as_ref().unwrap().id,
        before["active_issue"]["id"].as_str().unwrap()
    );
    assert_eq!(
        serde_json::to_value(&state.worker_bindings).unwrap(),
        before["worker_bindings"]
    );
    assert_eq!(
        state.attempts.len(),
        before["attempts"].as_array().unwrap().len()
    );
    assert!(state.rule_replay_pending && !state.e2e_current);
}

#[test]
fn replaced_issue_overview_remains_stale_and_cannot_authorize_a_plan() {
    let fixture = Fixture::new();
    fixture.confirm();
    let overview = query_rewrite_evidence_for_scope(
        fixture.context(),
        &RewriteWorkScope::Api { api: "/api".into() },
    )
    .unwrap();
    let mut state = fixture.state();
    state
        .active_issue
        .as_mut()
        .unwrap()
        .id
        .push_str("-replaced");
    fixture.store().save(&state).unwrap();
    assert!(
        inventory::api_for_ownership_evidence_id(fixture.root(), &state, &overview.evidence_id)
            .is_err()
    );
    let policy = fs::read(fixture.policy()).unwrap();
    let error = plan_rewrite_unified_rule(
        fixture.context(),
        RewriteUnifiedRulePlanOptions {
            file: fixture.proposal.clone(),
            evidence_id: overview.evidence_id,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("stale"), "{error}");
    assert!(!error.contains("current issue overview"));
    assert!(fixture.state().rule_plan.is_none());
    assert_eq!(fs::read(fixture.policy()).unwrap(), policy);
}

#[test]
fn rule_evidence_resolution_ignores_excluded_retained_issues_without_panicking() {
    use crate::rewrite::model::{RewriteApiStatus, RewritePhase};

    for skipped in [true, false] {
        let fixture = Fixture::new();
        fixture.confirm();
        let mut state = fixture.state();
        let mut retained = state.active_slice.clone();
        retained.api = "GET /retained".into();
        retained.source_route = "/retained".into();
        retained
            .active_issue
            .as_mut()
            .unwrap()
            .id
            .push_str("-retained");
        let mut item = state.api_inventory[0].clone();
        item.api = retained.api.clone();
        item.source_route = Some(retained.source_route.clone());
        if skipped {
            fs::write(
                fixture.root().join(".traffic-e2e/regression.yaml"),
                "skip:\n  - /retained\n",
            )
            .unwrap();
        } else {
            retained.phase = RewritePhase::SystemRepairRequired;
            item.status = RewriteApiStatus::SystemRepairRequired;
        }
        state.api_inventory.push(item);
        state.parked_slices.insert(retained.api.clone(), retained);
        fixture.store().save(&state).unwrap();

        let before = serde_json::to_value(fixture.state()).unwrap();
        let policy = fs::read(fixture.policy()).unwrap();
        for evidence_id in ["", "evidence-unknown"] {
            let error = plan_rewrite_unified_rule(
                fixture.context(),
                RewriteUnifiedRulePlanOptions {
                    file: fixture.proposal.clone(),
                    evidence_id: evidence_id.into(),
                },
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("stale"), "skipped={skipped}: {error}");
            assert_eq!(serde_json::to_value(fixture.state()).unwrap(), before);
            assert_eq!(fs::read(fixture.policy()).unwrap(), policy);
        }
        // A valid detail ID also scans the retained slices before resolution.
        // Excluded issues must not prevent the active worker's ordinary plan.
        assert!(fixture.plan().is_ok(), "skipped={skipped}");
    }
}
