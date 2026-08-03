use super::*;
use crate::rewrite::model::{RewriteIssue, RewriteIssueOwner, RewritePhase};

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
    )
    .unwrap_err();

    assert!(error.to_string().contains("evidence is stale"));
}
