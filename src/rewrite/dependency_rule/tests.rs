use super::*;
use crate::rewrite::model::{RewriteIssue, RewriteIssueOwner, RewritePhase};
use std::fs;
use tempfile::tempdir;

fn dependency_state() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-dependency".to_string(),
        kind: RewriteIssueKind::Dependency,
        owner: RewriteIssueOwner::SourceInvestigation,
        summary: "dependency evidence is dirty".to_string(),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });
    state.dependency_rule_plan = Some(RewriteDependencyRulePlanRecord {
        id: "dependency-plan-original".to_string(),
        issue_id: "issue-dependency".to_string(),
        evidence_id: "evidence-dirty-clusters".to_string(),
        name: "cache-warm".to_string(),
        source_evidence: "src/cache.rs:warm".to_string(),
        spec: RewriteDependencyRuleSpec::RedisScard {
            ports: vec![6379],
            keys: vec!["cache:key".to_string()],
            initial_load_timeout_ms: 60_000,
        },
        reused_existing: false,
        effective_name: None,
    });
    state
}

#[test]
fn persisted_plan_remains_applicable_after_plan_revision_bump() {
    let mut state = dependency_state();
    state.bump();

    let record = pending_plan_for_apply(&state, "dependency-plan-original").unwrap();

    assert_eq!(record.evidence_id, "evidence-dirty-clusters");
}

#[test]
fn apply_does_not_revalidate_revision_scoped_evidence() {
    let mut state = dependency_state();
    state.bump();

    let error = apply(
        Path::new("/missing-target"),
        &mut state,
        "dependency-plan-original",
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("requires a finalized case source")
    );
}

#[test]
fn pending_plan_evidence_can_replace_an_incomplete_preview() {
    let mut state = dependency_state();
    state.bump();

    validate_plan_evidence(
        Path::new("/missing-target"),
        &state,
        "issue-dependency",
        "evidence-dirty-clusters",
        &state.dependency_rule_plan.as_ref().unwrap().spec,
    )
    .unwrap();
}

#[test]
fn pending_plan_evidence_cannot_cross_issue_boundaries() {
    let state = dependency_state();

    let error = validate_plan_evidence(
        Path::new("/missing-target"),
        &state,
        "issue-other",
        "evidence-dirty-clusters",
        &state.dependency_rule_plan.as_ref().unwrap().spec,
    )
    .unwrap_err();

    assert!(error.to_string().contains("evidence is stale"));
}

#[test]
fn request_owned_classification_requires_target_implementation_without_a_rule_plan() {
    let target = tempdir().unwrap();
    let mut state = dependency_state();
    let issue = state.active_issue.clone().unwrap();
    let selector = serde_json::json!({
        "protocol": "motan",
        "group": "yf-tkv-rpc",
        "interface_name": "com.weibo.api.mcq.rpc.KafkaService",
        "method_name": "sender",
    });

    let report = classify_non_process_owned(
        target.path(),
        &mut state,
        issue,
        RewriteDependencyRulePlanOptions {
            evidence_id: "evidence-dirty-clusters".to_string(),
            ownership: RewriteDependencyOwnership::RequestOwned,
            name: None,
            source_evidence: Some(
                "TrafficProcessorImpl.java:onCompletion audit sender".to_string(),
            ),
            selector: RewriteDependencyRuleSelector::Motan {
                group: "yf-tkv-rpc".to_string(),
                interface_name: "com.weibo.api.mcq.rpc.KafkaService".to_string(),
                method_name: "sender".to_string(),
            },
        },
        selector,
    )
    .unwrap();

    assert_eq!(report.ownership, RewriteDependencyOwnership::RequestOwned);
    assert!(!report.process_owned_rule_applicable);
    assert!(report.target_implementation_required);
    assert!(report.plan_id.is_none());
    assert!(state.dependency_rule_plan.is_none());
    let issue = state.active_issue.as_ref().unwrap();
    assert_eq!(issue.owner, RewriteIssueOwner::TargetCode);
    assert!(
        issue
            .summary
            .contains("implement the recorded request-owned")
    );
    assert_eq!(
        issue.possible_causes,
        vec!["request_owned_dependency_not_implemented"]
    );
}

#[test]
fn unresolved_classification_preserves_source_investigation_without_a_rule_plan() {
    let target = tempdir().unwrap();
    let mut state = dependency_state();
    let issue = state.active_issue.clone().unwrap();

    let report = classify_non_process_owned(
        target.path(),
        &mut state,
        issue,
        RewriteDependencyRulePlanOptions {
            evidence_id: "evidence-dirty-clusters".to_string(),
            ownership: RewriteDependencyOwnership::Unresolved,
            name: None,
            source_evidence: None,
            selector: RewriteDependencyRuleSelector::RedisGet {
                ports: vec![6379],
                keys: vec!["cache:key".to_string()],
                initial_load_timeout_ms: 60_000,
            },
        },
        serde_json::json!({"protocol": "redis_get", "ports": [6379]}),
    )
    .unwrap();

    assert_eq!(report.ownership, RewriteDependencyOwnership::Unresolved);
    assert!(!report.process_owned_rule_applicable);
    assert!(!report.target_implementation_required);
    assert!(state.dependency_rule_plan.is_none());
    let issue = state.active_issue.as_ref().unwrap();
    assert_eq!(issue.owner, RewriteIssueOwner::SourceInvestigation);
    assert!(issue.summary.contains("determine whether"));
}

#[test]
fn redis_rule_application_is_queued_for_a_fresh_snapshot_recording() {
    let target = tempdir().unwrap();
    fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
    crate::rewrite::test_support::install_project_config(
        target.path(),
        "master",
        crate::config::AppConfig::default(),
        None,
    );
    let mut state = dependency_state();
    let applied = pending_cache_snapshot_refresh(&state, "dependency-plan-original")
        .unwrap()
        .unwrap();

    schedule_cache_snapshot_refresh(target.path(), &mut state, applied).unwrap();

    assert_eq!(state.phase, RewritePhase::AwaitingRecordingRefresh);
    let refresh = state.recording_refresh.unwrap();
    assert!(refresh.applied.is_empty());
    assert_eq!(refresh.dependency_rules.len(), 1);
    assert_eq!(refresh.dependency_rules[0].rule_name, "cache-warm");
    assert!(refresh.recording_run_id.is_none());
}
