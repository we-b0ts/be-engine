use super::*;
use crate::rewrite::model::RewriteDependencyRulePlanRecord;

fn state() -> RewriteState {
    let mut state = crate::rewrite::worker::tests::implementation_state_with_inventory(false);
    let issue_id = state.active_issue.as_ref().unwrap().id.clone();
    state.dependency_rule_plan = Some(serde_json::from_value::<RewriteDependencyRulePlanRecord>(json!({
        "id":"plan","issue_id":issue_id,"evidence_id":"evidence","name":"startup", "source_evidence":"startup.py:run opens a process-owned connection",
        "spec":{"kind":"http","authority":"service.test","method":"POST","path_prefix":"/connect"}
    })).unwrap());
    state
}

#[test]
fn recovery_preserves_source_proof_and_requests_fresh_verification_without_applying() {
    let mut state = state();
    let issue = state.active_issue.as_ref().unwrap().id.clone();
    let report = recover_slice(Path::new("/target"), &mut state, "plan").unwrap();
    assert_eq!(report["applied"], false);
    assert_eq!(report["retired_plan"]["name"], "startup");
    assert_eq!(
        report["retired_plan"]["source_evidence"],
        "startup.py:run opens a process-owned connection"
    );
    assert!(state.dependency_rule_plan.is_none());
    assert!(super::super::rule_replay::pending(&state.active_slice));
    assert!(!state.e2e_current);
    assert_eq!(state.active_issue.as_ref().unwrap().id, issue);
}

#[test]
fn recovery_rejects_other_plan_ids_and_changed_issues_without_changing_state() {
    let mut state = state();
    let before = serde_json::to_value(&state).unwrap();
    assert!(recover_slice(Path::new("/target"), &mut state, "other-plan").is_err());
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    state.active_issue.as_mut().unwrap().id = "new-issue".into();
    assert!(recover_slice(Path::new("/target"), &mut state, "plan").is_err());
    assert!(state.dependency_rule_plan.is_some());
}

#[test]
fn persisted_plan_recovers_only_after_evidence_loss_and_never_during_active_replay() {
    let target = crate::rewrite::worker::tests::configured_target();
    let root = target.path();
    std::fs::write(
        root.join(".traffic-e2e/Dockerfile.target"),
        "FROM scratch\n",
    )
    .unwrap();
    let source = root.join(".traffic-e2e/local/artifacts/recordings/recording");
    std::fs::create_dir_all(&source).unwrap();
    let paths = crate::e2e_run::jwt_evidence::test_support::install_attempt(
        root,
        &source,
        &[],
        chrono::Utc::now(),
    );
    for path in [&paths.replay, &paths.assertions, &paths.aggregate] {
        std::fs::write(path, "{}").unwrap();
    }
    let sidecar = crate::replay::report::dependency_evidence_path(&paths.replay);
    std::fs::write(&sidecar, "{}").unwrap();
    let mut state = state();
    state.case_source = Some(source);
    state.group_id = Some("GET /api".into());
    let store = RewriteStore::new(root).unwrap();
    store.save(&state).unwrap();
    let context = || RewriteContext {
        target_root: root.into(),
    };
    assert!(!evidence_missing(root, &state).unwrap());
    assert!(required_action(root, &state).is_none());
    assert!(recover_rewrite_rule_plan(context(), "plan").is_err());
    std::fs::remove_file(&sidecar).unwrap();
    assert!(evidence_missing(root, &state).unwrap());
    let action = required_action(root, &state).unwrap();
    let super::super::model::RewriteAction::PlanApplyRequired { command, .. } = action else {
        panic!("recover the pending plan")
    };
    assert!(
        command
            .argv
            .ends_with(&["rule".into(), "recover".into(), "plan".into()])
    );
    let active = paths
        .replay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".active");
    std::fs::create_dir(&active).unwrap();
    assert!(recover_rewrite_rule_plan(context(), "plan").is_err());
    assert!(
        store
            .load()
            .unwrap()
            .unwrap()
            .dependency_rule_plan
            .is_some()
    );
    std::fs::remove_dir(active).unwrap();
    let result = recover_rewrite_rule_plan(context(), "plan").unwrap();
    assert_eq!(result["status"], "fresh_replay_required");
    let recovered = store.load().unwrap().unwrap();
    assert!(recovered.rule_replay_pending && !recovered.e2e_current);
    assert!(recovered.dependency_rule_plan.is_none());
    assert!(recover_rewrite_rule_plan(context(), "plan").is_err());
}

fn policy_fixture(
    kind: &str,
) -> (
    tempfile::TempDir,
    RewriteState,
    crate::E2eResponseRuleEvidence,
) {
    if kind == "response_jwts" {
        return super::super::rule::response_jwt_plan_fixture();
    }
    let target = crate::rewrite::worker::tests::configured_target();
    let root = target.path();
    std::fs::write(
        root.join(".traffic-e2e/Dockerfile.target"),
        "FROM scratch\n",
    )
    .unwrap();
    let source = root.join(".traffic-e2e/local/artifacts/recordings/recording");
    std::fs::create_dir_all(&source).unwrap();
    let paths = crate::e2e_run::jwt_evidence::test_support::install_attempt(
        root,
        &source,
        &[],
        chrono::Utc::now(),
    );
    let policy_path = root.join(".traffic-e2e/verification.yaml");
    let fingerprint = crate::validate_replay_policy(&policy_path)
        .unwrap()
        .fingerprint;
    std::fs::write(
        &paths.replay,
        json!({"finalized":true,"replay_policy":{"fingerprint":fingerprint}}).to_string(),
    )
    .unwrap();
    std::fs::write(
        &paths.assertions,
        json!({"policy_fingerprint":fingerprint}).to_string(),
    )
    .unwrap();
    std::fs::write(&paths.aggregate, "{}").unwrap();
    std::fs::write(
        crate::replay::report::dependency_evidence_path(&paths.replay),
        r#"{"exchanges":[{"sequence":1,"status":"available"}]}"#,
    )
    .unwrap();
    let mut state = state();
    state.dependency_rule_plan = None;
    state.case_source = Some(source);
    state.group_id = Some("GET /api".into());
    state.e2e_current = true;
    let mut record = json!({
        "id":"plan", "issue_id":state.active_issue.as_ref().unwrap().id,
        "evidence_id":"evidence", "kind":kind,"json_pointer":"",
        "source_evidence":"auth.rs: source and target use the same JWT key and expiry contract"
    });
    record[kind] = match kind {
        "jwt" => json!({
            "rule":{"id":"jwt","header":"authorization","scheme":"bearer","profile":"session"},
            "profile":{"signing_key_ref":"session","algorithm":"HS256","time":"preserve_relative"},
            "policy_revision":crate::e2e_run::jwt_evidence::digest(&std::fs::read(&policy_path).unwrap()),
            "evidence_revision":"evidence", "leeway_seconds":60
        }),
        "response_jwts" => json!([{
            "pointer":"/token", "algorithm":"HS256",
            "signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},
            "source_evidence":"auth.rs: signs response tokens with SECRET_KEY"
        }]),
        "header_dates" => json!([{
            "header":"content-disposition", "parameter":"filename", "format":"%Y-%m-%d",
            "source_evidence":"export.rs: filename includes the current UTC date"
        }]),
        "dependency_request" => json!({"id":"time","kind":"redis","command":"SET"}),
        "dynamic_value" => json!({
            "id":"identity", "api":"/api", "targets":[{"host":"service.test","port":80}],
            "capture":{"protocol":"http","target":{"host":"service.test","port":80},
                "method":"POST","path":"/create","json_pointer":"/id"},
            "source_evidence":"client.rs: generates a request-local identifier"
        }),
        _ => panic!("unsupported fixture kind"),
    };
    if kind != "jwt" {
        record["generated_witnesses"] = json!([[policy_path, fingerprint]]);
    }
    state.rule_plan = Some(serde_json::from_value(record).unwrap());
    RewriteStore::new(root).unwrap().save(&state).unwrap();
    (target, state, paths)
}

fn assert_plan_action(action: super::super::model::RewriteAction, operation: &str) {
    let super::super::model::RewriteAction::PlanApplyRequired { command, .. } = action else {
        panic!("expected pending-plan action, got {action:?}")
    };
    assert!(
        command
            .argv
            .ends_with(&["rule".into(), operation.into(), "plan".into()])
    );
}

const POLICY_PLAN_KINDS: [&str; 5] = [
    "jwt",
    "response_jwts",
    "header_dates",
    "dependency_request",
    "dynamic_value",
];

#[test]
fn scheduler_recovers_every_supported_policy_stale_plan_without_applying_or_passing() {
    for kind in POLICY_PLAN_KINDS {
        let (target, state, paths) = policy_fixture(kind);
        let root = target.path();
        let policy_path = root.join(".traffic-e2e/verification.yaml");
        let mut policy = std::fs::read(&policy_path).unwrap();
        policy.extend_from_slice(b"# another API advanced the shared verification policy\n");
        std::fs::write(&policy_path, &policy).unwrap();
        let sidecar = crate::replay::report::dependency_evidence_path(&paths.replay);
        let finite_evidence = std::fs::read(&sidecar).unwrap();
        let replay = std::fs::read(&paths.replay).unwrap();
        let original_plan = serde_json::to_value(state.rule_plan.as_ref().unwrap()).unwrap();
        assert_plan_action(action::state_action(root, &state), "recover");
        let result = recover_rewrite_rule_plan(
            RewriteContext {
                target_root: root.into(),
            },
            "plan",
        )
        .unwrap();
        assert_eq!(result["applied"], false);
        assert_eq!(result["status"], "fresh_replay_required");
        assert_eq!(result["retired_plan"], original_plan);
        assert_eq!(std::fs::read(&policy_path).unwrap(), policy);
        assert_eq!(std::fs::read(sidecar).unwrap(), finite_evidence);
        assert_eq!(std::fs::read(&paths.replay).unwrap(), replay);
        let recovered = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
        assert!(recovered.rule_plan.is_none());
        assert!(recovered.rule_replay_pending && !recovered.e2e_current);
        assert_eq!(
            serde_json::to_value(&recovered.active_issue).unwrap(),
            serde_json::to_value(&state.active_issue).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&recovered.attempts).unwrap(),
            serde_json::to_value(&state.attempts).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&recovered.api_inventory).unwrap(),
            serde_json::to_value(&state.api_inventory).unwrap()
        );
        assert_eq!(recovered.phase, state.phase);
    }
}

#[test]
fn current_policy_plans_keep_the_apply_action_and_cannot_be_retired() {
    for kind in POLICY_PLAN_KINDS {
        let (target, state, _) = policy_fixture(kind);
        let root = target.path();
        let store = RewriteStore::new(root).unwrap();
        let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
        let policy = std::fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap();
        assert_plan_action(action::state_action(root, &state), "apply");
        assert!(
            recover_rewrite_rule_plan(
                RewriteContext {
                    target_root: root.into()
                },
                "plan"
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
            before
        );
        assert_eq!(
            std::fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap(),
            policy
        );
    }
}

#[test]
fn policy_staleness_does_not_bypass_plan_issue_or_active_attempt_guards() {
    for guard in ["plan_id", "issue_id", "active_attempt"] {
        let (target, mut state, paths) = policy_fixture("jwt");
        let root = target.path();
        let policy_path = root.join(".traffic-e2e/verification.yaml");
        let policy = format!(
            "{}# changed\n",
            std::fs::read_to_string(&policy_path).unwrap()
        );
        std::fs::write(&policy_path, &policy).unwrap();
        if guard == "issue_id" {
            state.active_issue.as_mut().unwrap().id = "different-issue".into();
        } else if guard == "active_attempt" {
            std::fs::create_dir(
                paths
                    .replay
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join(".active"),
            )
            .unwrap();
        }
        let store = RewriteStore::new(root).unwrap();
        store.save(&state).unwrap();
        let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
        let plan_id = if guard == "plan_id" {
            "different-plan"
        } else {
            "plan"
        };
        assert!(
            recover_rewrite_rule_plan(
                RewriteContext {
                    target_root: root.into()
                },
                plan_id
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
            before
        );
        assert_eq!(std::fs::read_to_string(policy_path).unwrap(), policy);
    }
}
