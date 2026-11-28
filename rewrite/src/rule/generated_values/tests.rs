//! Retired authoring remains recoverable; unified transactions own new plans.
use super::*;
use crate::{RewriteContext, store::RewriteStore};
use std::fs;

fn options() -> RewriteRulePlanOptions {
    RewriteRulePlanOptions {
        response_jwts: Vec::new(),
        header_dates: Vec::new(),
        dynamic_value: None,
        mysql_time: None,
        redis_time: None,
        dependency_request: None,
        evidence_id: "old-evidence".into(),
        jwt: None,
        body_codec: ResponseBodyCodec::Json,
        kind: None,
        time: None,
        json_pointer: None,
        source_evidence: None,
        source_example: None,
        target_example: None,
        separator: None,
        unordered_paths: Vec::new(),
        unordered_joined_string_paths: Vec::new(),
        docx_timestamps: Vec::new(),
    }
}

fn redis_time() -> crate::DynamicValueRedisTimeRule {
    serde_json::from_value(json!({"id":"item-time", "method":"GET",
        "time_values":[{"json_pointer":"/timestamp","format":"unix_milliseconds"}],
        "source_evidence":"ItemFactory:create stores the current millisecond timestamp"}))
    .unwrap()
}

#[test]
fn redis_companion_records_remain_readable_for_pending_plan_recovery() {
    let legacy = json!({"id":"plan","issue_id":"issue","kind":"dynamic_value",
        "json_pointer":"","evidence_id":"evidence"});
    let mut record: RewriteRulePlanRecord = serde_json::from_value(legacy).unwrap();
    assert!(record.redis_time.is_none());
    assert!(
        serde_json::to_value(&record)
            .unwrap()
            .get("redis_time")
            .is_none()
    );
    record.redis_time = Some(redis_time());
    let restored: RewriteRulePlanRecord =
        serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap();
    assert_eq!(restored.redis_time, Some(redis_time()));
}

#[test]
fn retired_generated_planner_preserves_policy_source_and_workflow() {
    let target = crate::worker::tests::configured_target();
    let root = target.path();
    let mut state = crate::worker::tests::implementation_state_with_inventory(false);
    let source = root.join("source.jsonl");
    fs::write(&source, "immutable recorded bytes").unwrap();
    let policy = root.join(".traffic-e2e/policy.yaml");
    let policy_before = fs::read(&policy).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    for companion in [None, Some(redis_time())] {
        let mut input = options();
        input.redis_time = companion;
        let error = plan(root, &mut state, input).unwrap_err();
        assert!(error.to_string().contains("retired"));
        assert!(error.to_string().contains("project.policy"));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
        assert_eq!(fs::read(&policy).unwrap(), policy_before);
        assert_eq!(fs::read(&source).unwrap(), b"immutable recorded bytes");
    }
}

#[test]
fn companion_validation_still_rejects_ambiguous_internal_dtos() {
    assert!(validate_companions(false, false, true).is_err());
    assert!(validate_companions(true, true, true).is_err());
    assert!(validate_companions(true, false, true).is_ok());
}

#[test]
fn retired_generated_pending_plan_recovers_without_reading_or_rewriting_policy() {
    for kind in ["dynamic_value", "dynamic_value_redis_time", "response_jwt"] {
        let target = crate::worker::tests::configured_target();
        let root = target.path();
        let mut state = crate::worker::tests::implementation_state_with_inventory(false);
        let issue = state.active_issue.as_ref().unwrap().id.clone();
        state.rule_plan = Some(
            serde_json::from_value(json!({"id":"retired-plan",
            "issue_id":issue,"kind":kind,"json_pointer":"","evidence_id":"old-evidence"}))
            .unwrap(),
        );
        let store = RewriteStore::new(root).unwrap();
        store.save(&state).unwrap();
        let before = serde_json::to_value(&state).unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        let policy_before = fs::read(&policy).unwrap();
        let context = || RewriteContext {
            target_root: root.into(),
        };
        let error = crate::apply_rewrite_rule(context(), "retired-plan").unwrap_err();
        assert!(error.to_string().contains("retired"));
        assert_eq!(
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
            before
        );
        crate::worker::confirm(crate::worker::RewriteWorkerConfirmOptions {
            target_root: root.into(),
            work_scope: crate::RewriteWorkScope::Api { api: "/api".into() },
            worktree: Some(root.into()),
            agent_handle: "retired-generated-worker".into(),
            agent_name: None,
        })
        .unwrap();
        let report = crate::recover_rewrite_rule_plan(context(), "retired-plan").unwrap();
        assert_eq!(report["status"], "fresh_replay_required");
        assert_eq!(report["applied"], false);
        let recovered = store.load().unwrap().unwrap();
        assert!(
            recovered.rule_plan.is_none()
                && recovered.rule_replay_pending
                && !recovered.e2e_current
        );
        assert_eq!(fs::read(policy).unwrap(), policy_before);
    }
}
