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
