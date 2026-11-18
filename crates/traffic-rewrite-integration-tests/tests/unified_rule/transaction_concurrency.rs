//! Real preflight while another API owns the long coordinator transaction.
use super::*;
use crate::{
    model::RewriteAction,
    traffic_operation::{self, TrafficOperationClaim, TrafficOperationKind},
};

fn run_root(fixture: &Fixture) -> PathBuf {
    fixture
        .paths
        .replay
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "focused"))
        .unwrap()
        .parent()
        .unwrap()
        .into()
}

fn active(fixture: &Fixture, api: &str) -> PathBuf {
    let root = run_root(fixture).join(".active");
    fs::create_dir_all(&root).unwrap();
    let path = fixture
        .paths
        .replay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("state.yaml");
    let mut state: serde_json::Value =
        serde_yaml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    state["apis"][0]["group_id"] = json!(api);
    fs::write(
        root.join("state.yaml"),
        serde_yaml::to_string(&state).unwrap(),
    )
    .unwrap();
    root
}

#[test]
fn planning_during_other_api_replay_survives_its_snapshot_save_and_apply_waits() {
    let fixture = Fixture::new();
    fixture.confirm();
    let store = fixture.store();
    let mut in_flight = fixture.state();
    let lock = store.lock().unwrap();
    let operation =
        crate::internal_runtime::root(fixture.root()).join("rewrite/operations/current.json");
    fs::create_dir_all(operation.parent().unwrap()).unwrap();
    write(
        &operation,
        json!({"id":"other-operation","pid":unsafe {libc::getppid()} as u32,"finished":false,
        "request":{"kind":"next","api":"GET /other","source_route":null,"execution_mode":"auto_next"}}),
    );
    let active = active(&fixture, "GET /other");
    let claim = traffic_operation::claim_current(
        fixture.root(),
        "other-replay".into(),
        TrafficOperationKind::Replay,
        Some("GET /other".into()),
    )
    .unwrap();
    let TrafficOperationClaim::Acquired(traffic) = claim else {
        panic!("claim")
    };
    let snapshot_path = crate::internal_runtime::root(fixture.root()).join("rewrite/state.json");
    let before = fs::read(&snapshot_path).unwrap();
    let policy = fs::read(fixture.policy()).unwrap();

    let plan = fixture.plan().unwrap();
    assert_eq!(
        fs::read(&snapshot_path).unwrap(),
        before,
        "Plan must not overwrite in-flight state"
    );
    assert_eq!(fixture.state().rule_plan.as_ref().unwrap().id, plan.plan_id);
    let wait = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(wait.traffic_e2e_report["status"], "wait_required");
    assert_eq!(wait.traffic_e2e_report["applied"], false);
    assert_eq!(wait.traffic_e2e_report["queued"], false);
    assert_eq!(
        wait.traffic_e2e_report["action"]["details"]["blocking_api"],
        "/other"
    );
    assert_eq!(fs::read(fixture.policy()).unwrap(), policy);

    // The coordinator finishes using its older in-memory snapshot. New plans
    // must be folded in without discarding its new result or worker feedback.
    in_flight.recording_rejection = Some("retained coordinator result".into());
    store.save(&in_flight).unwrap();
    assert_eq!(
        fixture.state().recording_rejection.as_deref(),
        Some("retained coordinator result")
    );
    assert_eq!(fixture.state().rule_plan.as_ref().unwrap().id, plan.plan_id);
    fs::remove_dir_all(active).unwrap();
    drop(traffic);
    drop(lock);
    fs::remove_file(operation).unwrap();
    let action = crate::rule_plans::idle_action(fixture.root(), &fixture.state())
        .unwrap()
        .unwrap();
    let RewriteAction::PlanApplyRequired { command, .. } = action else {
        panic!("pending plan")
    };
    assert!(command.argv.contains(&plan.plan_id));
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert!(fixture.state().rule_plan.is_none());
    store.save(&fixture.state()).unwrap();
    assert!(
        fixture.state().rule_plan.is_none(),
        "applied events cannot resurrect a plan"
    );
}

#[test]
fn own_active_attempt_and_unknown_scope_cannot_supply_plan_evidence() {
    for api in ["GET /api", "GET /other"] {
        let fixture = Fixture::new();
        fixture.confirm();
        let evidence_id = fixture.evidence().evidence_id;
        let directory = active(&fixture, api);
        if api == "GET /other" {
            fs::remove_file(directory.join("state.yaml")).unwrap();
        }
        assert!(
            plan_rewrite_unified_rule(
                fixture.context(),
                RewriteUnifiedRulePlanOptions {
                    file: fixture.proposal.clone(),
                    evidence_id
                }
            )
            .is_err()
        );
        assert!(fixture.state().rule_plan.is_none());
    }
}

#[test]
fn replay_reservation_blocks_planning_its_route_before_active_files_exist() {
    let fixture = Fixture::new();
    fixture.confirm();
    let claim = traffic_operation::claim_current(
        fixture.root(),
        "own-replay".into(),
        TrafficOperationKind::Replay,
        Some("POST /api".into()),
    )
    .unwrap();
    let TrafficOperationClaim::Acquired(_traffic) = claim else {
        panic!("claim")
    };
    let error = fixture.plan().unwrap_err();
    assert!(format!("{error:#}").contains("Replay is reserved"));
}

#[test]
fn unrelated_prepared_index_bytes_do_not_invalidate_a_plan() {
    let fixture = Fixture::new();
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let index = run_root(&fixture).join("case-groups.json");
    // Preparing a different group can rewrite the shared index. This harmless
    // rewrite must not stand in for the selected group's semantic identity.
    let mut bytes = fs::read(&index).unwrap();
    bytes.extend_from_slice(b"\n\n");
    fs::write(index, bytes).unwrap();
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
}

#[test]
fn json_identity_plan_survives_code_and_timing_drift_but_keeps_policy_cas() {
    for policy_changed in [false, true] {
        let fixture = Fixture::new();
        fixture
            .replace_response_bodies(br#"{"id":"old","stable":1}"#, br#"{"id":"new","stable":2}"#);
        write(
            &fixture.proposal,
            json!({"format":"traffic-policy/v3","json":{"fields":{
                "/id":{"kind":"identity","formats":[{"string":64}]}
            }}}),
        );
        fixture.confirm();
        let code = fixture.root().join("other-api.rs");
        fs::write(&code, "fn other_api() {}\n").unwrap();
        let regression = fixture.root().join(".traffic-e2e/regression.yaml");
        fs::write(
            &regression,
            "replay_timing: fast\nreplay_interval_cap_ms: 3\n",
        )
        .unwrap();
        let plan = fixture.plan().unwrap();
        assert_eq!(plan.traffic_e2e_report["target_replay_drift_at_plan"], true);
        let preflight = &plan.traffic_e2e_report["preflight"];
        assert_eq!(
            preflight["target_comparison_failures"][0]["case_id"],
            "00000000-0000-4000-8000-000000000001"
        );
        assert_eq!(preflight["independent_target_validations"], 0);
        fs::write(&code, "fn other_api() -> bool { true }\n").unwrap();
        if policy_changed {
            fs::write(
                fixture.policy(),
                "format: traffic-policy/v3\n# concurrent policy edit\n",
            )
            .unwrap();
            let error = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap_err();
            assert!(format!("{error:#}").contains("policy changed after planning"));
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            assert_eq!(
                applied.traffic_e2e_report["target_replay_drift_at_apply"],
                true
            );
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        }
    }
}

#[test]
fn stale_plan_recovery_preserves_a_newer_failure_issue() {
    let fixture = Fixture::new();
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().id = "new-failure".into();
    state.rule_replay_pending = false;
    fixture.store().save(&state).unwrap();
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
    let report = recover_rewrite_rule_plan(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(report["status"], "retired_stale_plan");
    let state = fixture.state();
    assert_eq!(state.active_issue.as_ref().unwrap().id, "new-failure");
    assert!(!state.rule_replay_pending);
    assert!(state.rule_plan.is_none());
}

#[tokio::test]
async fn pending_plan_precedes_next_replay_after_another_api_passes_or_needs_impl() {
    use crate::model::{RewriteApiProgress, RewriteApiStatus, RewritePhase};
    for passed in [true, false] {
        let fixture = Fixture::new();
        fixture.confirm();
        let store = fixture.store();
        let mut in_flight = fixture.state();
        let original = in_flight.active_slice.clone();
        in_flight
            .parked_slices
            .insert(original.api.clone(), original);
        in_flight.api = "GET /other".into();
        in_flight.source_route = "/other".into();
        in_flight.group_id = Some("GET /other".into());
        in_flight.active_issue.as_mut().unwrap().id = "other-failure".into();
        in_flight.api_inventory.push(RewriteApiProgress {
            api: "GET /other".into(),
            source_route: Some("/other".into()),
            status: RewriteApiStatus::Active,
            attempts: 1,
            e2e_current: false,
            verified_target_fingerprint: None,
        });
        store.save(&in_flight).unwrap();
        let lock = store.lock().unwrap();
        let claim = traffic_operation::claim_current(
            fixture.root(),
            "other-replay".into(),
            TrafficOperationKind::Replay,
            Some("GET /other".into()),
        )
        .unwrap();
        let TrafficOperationClaim::Acquired(traffic) = claim else {
            panic!("claim")
        };
        let plan = fixture.plan().unwrap();

        in_flight.phase = if passed {
            RewritePhase::SliceComplete
        } else {
            RewritePhase::ImplementationRequired
        };
        if passed {
            in_flight.active_issue = None;
        }
        in_flight.api_inventory.last_mut().unwrap().status = if passed {
            RewriteApiStatus::Complete
        } else {
            RewriteApiStatus::ImplementationRequired
        };
        store.save(&in_flight).unwrap();
        drop(traffic);
        drop(lock);
        fs::write(
            fixture.root().join(".traffic-e2e/regression.yaml"),
            "auto_next: true\n",
        )
        .unwrap();
        let envelope = crate::next_rewrite(crate::RewriteNextOptions {
            target_root: fixture.root().into(),
            api: None,
            source_route: None,
        })
        .await
        .unwrap();
        let RewriteAction::PlanApplyRequired { command, .. } = envelope.action else {
            panic!("plan must precede continuation")
        };
        assert!(command.argv.contains(&plan.plan_id));
        assert!(command.argv.contains(&"apply".into()));
        assert!(!envelope.terminal_allowed);
        assert_eq!(fixture.state().phase, in_flight.phase);
        assert_eq!(
            fixture.state().active_issue.as_ref().map(|i| &i.id),
            in_flight.active_issue.as_ref().map(|i| &i.id)
        );
        apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(fixture.state().phase, in_flight.phase);
        if !passed {
            assert_eq!(
                fixture.state().active_issue.as_ref().unwrap().id,
                "other-failure"
            );
            assert!(!fixture.state().rule_replay_pending);
        }
    }
}
