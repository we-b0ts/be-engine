use super::*;

fn fixture(
    dynamic: bool,
) -> (
    tempfile::TempDir,
    RewriteState,
    crate::E2eResponseRuleEvidence,
) {
    let (target, mut state, paths) = policy_fixture("dynamic_value");
    let policy_path = target.path().join(".traffic-e2e/verification.yaml");
    if dynamic {
        let rule = state
            .rule_plan
            .as_ref()
            .unwrap()
            .dynamic_value
            .as_ref()
            .unwrap();
        let mut policy: Value =
            serde_yaml::from_str(&std::fs::read_to_string(&policy_path).unwrap()).unwrap();
        let mut binding = serde_json::to_value(rule).unwrap();
        binding["kind"] = json!("dynamic_value");
        policy["dependency_rules"]
            .as_array_mut()
            .unwrap()
            .push(binding);
        std::fs::write(&policy_path, serde_yaml::to_string(&policy).unwrap()).unwrap();
    }
    let current = crate::validate_replay_policy(&policy_path).unwrap();
    std::fs::write(
        &paths.replay,
        json!({"finalized":true,"replay_policy":{"fingerprint":current.fingerprint}}).to_string(),
    )
    .unwrap();
    let mut plan = super::state().dependency_rule_plan.clone().unwrap();
    plan.issue_id = state.active_issue.as_ref().unwrap().id.clone();
    plan.spec = serde_json::from_value(json!({
        "kind":"mysql_sql_time", "selector": {
            "target_host":"db.internal", "target_port":3306, "database":"app", "username":"user",
            "sql":"UPDATE keys SET stamp=? WHERE id=?", "value_index":0,
            "format":"%Y-%m-%d %H:%M:%S%.f"
        }
    }))
    .unwrap();
    state.rule_plan = None;
    state.dependency_rule_plan = Some(plan);
    state.source_revision = Some("source-revision".into());
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    (target, state, paths)
}

fn advance_policy(root: &Path) -> Vec<u8> {
    let path = root.join(".traffic-e2e/verification.yaml");
    let mut policy = std::fs::read(&path).unwrap();
    policy.extend_from_slice(b"# another API applied a reviewed rule\n");
    std::fs::write(path, &policy).unwrap();
    policy
}

#[test]
fn mysql_time_policy_staleness_rejects_apply_and_offers_non_applying_recovery() {
    let (target, mut state, paths) = fixture(true);
    let root = target.path();
    let policy = advance_policy(root);
    let before = serde_json::to_value(&state).unwrap();
    let error = crate::rewrite::dependency_rule::apply(root, &mut state, "plan")
        .unwrap_err()
        .to_string();
    assert!(error.contains("different policy"), "{error}");
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    assert_plan_action(action::state_action(root, &state), "recover");
    let replay = std::fs::read(&paths.replay).unwrap();
    let original = serde_json::to_value(state.dependency_rule_plan.as_ref().unwrap()).unwrap();
    let result = recover_rewrite_rule_plan(
        RewriteContext {
            target_root: root.into(),
        },
        "plan",
    )
    .unwrap();
    assert_eq!(result["retired_plan"], original);
    assert_eq!(result["applied"], false);
    let after = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    assert!(after.dependency_rule_plan.is_none());
    assert!(crate::rewrite::rule_replay::pending(&after.active_slice));
    assert!(crate::rewrite::replay_admission::slice_ready(
        &after,
        &after.active_slice
    ));
    assert_eq!(
        serde_json::to_value(&after.active_issue).unwrap(),
        serde_json::to_value(&state.active_issue).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&after.attempts).unwrap(),
        serde_json::to_value(&state.attempts).unwrap()
    );
    assert_eq!(
        std::fs::read(root.join(".traffic-e2e/verification.yaml")).unwrap(),
        policy
    );
    assert_eq!(std::fs::read(paths.replay).unwrap(), replay);
}

#[test]
fn mysql_time_recovery_preserves_current_plans_and_legacy_evidence_without_dynamic_bindings() {
    for dynamic in [true, false] {
        let (target, state, _) = fixture(dynamic);
        let root = target.path();
        if !dynamic {
            advance_policy(root);
        }
        let before = serde_json::to_value(&state).unwrap();
        assert!(!evidence_unusable(root, &state).unwrap());
        assert!(required_action(root, &state).is_none());
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
            serde_json::to_value(RewriteStore::new(root).unwrap().load().unwrap().unwrap())
                .unwrap(),
            before
        );
    }
}

#[test]
fn mysql_time_recovery_preserves_plan_issue_and_active_replay_guards() {
    for guard in ["plan_id", "issue_id", "active_replay"] {
        let (target, mut state, paths) = fixture(true);
        let root = target.path();
        let policy = advance_policy(root);
        if guard == "issue_id" {
            state.active_issue.as_mut().unwrap().id = "changed-issue".into();
        } else if guard == "active_replay" {
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
        let id = if guard == "plan_id" {
            "other-plan"
        } else {
            "plan"
        };
        assert!(
            recover_rewrite_rule_plan(
                RewriteContext {
                    target_root: root.into()
                },
                id
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
fn mysql_time_recovery_updates_only_the_owner_parked_slice() {
    let (target, mut state, _) = fixture(true);
    let root = target.path();
    advance_policy(root);
    let owner = state.api.clone();
    state
        .parked_slices
        .insert(owner.clone(), state.active_slice.clone());
    state.api = "GET /other".into();
    state.active_issue.as_mut().unwrap().id = "other-issue".into();
    state.dependency_rule_plan = None;
    let active = serde_json::to_value(&state.active_slice).unwrap();
    RewriteStore::new(root).unwrap().save(&state).unwrap();
    let result = recover_rewrite_rule_plan(
        RewriteContext {
            target_root: root.into(),
        },
        "plan",
    )
    .unwrap();
    assert_eq!(result["applied"], false);
    let after = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    assert_eq!(serde_json::to_value(&after.active_slice).unwrap(), active);
    let recovered = &after.parked_slices[&owner];
    assert!(recovered.dependency_rule_plan.is_none());
    assert!(crate::rewrite::rule_replay::pending(recovered));
    assert!(crate::rewrite::replay_admission::slice_ready(
        &after, recovered
    ));
}
