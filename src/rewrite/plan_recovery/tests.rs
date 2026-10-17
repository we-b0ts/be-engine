//! Retired serialized plans preserve proof, but cannot authorize policy writes.
use super::*;
use crate::rewrite::model::{RewriteDependencyRulePlanRecord, RewriteRulePlanRecord};
use crate::rewrite::worker::{self, RewriteWorkerConfirmOptions};

fn state() -> RewriteState {
    let mut state = crate::rewrite::worker::tests::implementation_state_with_inventory(false);
    let issue_id = state.active_issue.as_ref().unwrap().id.clone();
    state.dependency_rule_plan = Some(serde_json::from_value::<RewriteDependencyRulePlanRecord>(json!({
        "id":"plan","issue_id":issue_id,"evidence_id":"evidence","name":"startup",
        "source_evidence":"startup.py:run opens a process-owned connection",
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

fn fixture(
    kind: &str,
) -> (
    tempfile::TempDir,
    RewriteState,
    crate::E2eResponseRuleEvidence,
) {
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
    let mut state = state();
    state.case_source = Some(source);
    state.group_id = Some("GET /api".into());
    if kind == "dependency_mysql_time" {
        state.dependency_rule_plan.as_mut().unwrap().spec = serde_json::from_value(json!({
            "kind":"mysql_sql_time","selector":{"target_host":"db.test","target_port":3306,
                "database":"app","username":"writer","sql":"UPDATE keys SET stamp=? WHERE id=?",
                "value_index":0,"format":"%Y-%m-%d %H:%M:%S%.f"}
        }))
        .unwrap();
    } else if kind != "dependency" {
        state.dependency_rule_plan = None;
        state.rule_plan = Some(
            serde_json::from_value::<RewriteRulePlanRecord>(json!({
                "id":"plan","issue_id":state.active_issue.as_ref().unwrap().id,
                "evidence_id":"evidence","kind":kind,"json_pointer":"/token",
                "source_evidence":"source/auth.rs:12 keeps the original issuance and expiry proof"
            }))
            .unwrap(),
        );
    }
    RewriteStore::new(root).unwrap().save(&state).unwrap();
    (target, state, paths)
}

fn confirm(root: &Path) {
    worker::confirm(RewriteWorkerConfirmOptions {
        target_root: root.into(),
        work_scope: super::super::RewriteWorkScope::Api { api: "/api".into() },
        worktree: Some(root.into()),
        agent_handle: "retired-plan-worker".into(),
        agent_name: None,
    })
    .unwrap();
}

#[test]
fn every_retired_plan_requires_recovery_even_when_its_old_evidence_is_present() {
    for kind in [
        "dependency",
        "dependency_mysql_time",
        "jwt",
        "response_jwts",
        "header_dates",
        "dependency_request",
        "dynamic_value",
    ] {
        let (target, state, _) = fixture(kind);
        let root = target.path();
        let policy = root.join(".traffic-e2e/policy.yaml");
        let original = std::fs::read(&policy).unwrap();
        assert!(evidence_unusable(root, &state).unwrap());
        let action = required_action(root, &state).unwrap();
        let super::super::model::RewriteAction::PlanApplyRequired { command, .. } = action else {
            panic!("recover the retired plan")
        };
        assert!(
            command
                .argv
                .ends_with(&["rule".into(), "recover".into(), "plan".into()])
        );
        let context = || RewriteContext {
            target_root: root.into(),
        };
        assert!(recover_rewrite_rule_plan(context(), "plan").is_err());
        confirm(root);
        assert!(crate::rewrite::apply_rewrite_rule(context(), "plan").is_err());
        let original_plan = if let Some(plan) = &state.rule_plan {
            serde_json::to_value(plan).unwrap()
        } else {
            serde_json::to_value(state.dependency_rule_plan.as_ref().unwrap()).unwrap()
        };
        let recovered = recover_rewrite_rule_plan(context(), "plan").unwrap();
        assert_eq!(recovered["retired_plan"], original_plan);
        assert_eq!(recovered["applied"], false);
        assert_eq!(std::fs::read(policy).unwrap(), original);
        let state = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
        assert!(state.rule_plan.is_none() && state.dependency_rule_plan.is_none());
        assert!(state.rule_replay_pending && !state.e2e_current);
    }
}

#[test]
fn retired_plan_recovery_keeps_issue_id_and_active_attempt_guards() {
    for guard in ["plan_id", "issue_id", "active_attempt"] {
        let (target, mut state, paths) = fixture("dependency_request");
        let root = target.path();
        if guard == "issue_id" {
            state.active_issue.as_mut().unwrap().id = "different-issue".into();
        }
        RewriteStore::new(root).unwrap().save(&state).unwrap();
        confirm(root);
        if guard == "active_attempt" {
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
        let before =
            serde_json::to_value(RewriteStore::new(root).unwrap().load().unwrap().unwrap())
                .unwrap();
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
            serde_json::to_value(RewriteStore::new(root).unwrap().load().unwrap().unwrap())
                .unwrap(),
            before
        );
    }
}
