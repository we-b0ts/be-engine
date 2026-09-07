use super::*;
use crate::rewrite::model::{RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase};

fn response_state() -> RewriteState {
    let mut state = crate::rewrite::test_state();
    state.phase = RewritePhase::ImplementationRequired;
    state.active_issue = Some(RewriteIssue {
        id: "issue-response".to_string(),
        kind: RewriteIssueKind::Response,
        owner: RewriteIssueOwner::TargetCode,
        summary: "response differs".to_string(),
        pointer_pattern: Some("/request_id".to_string()),
        representative: None,
        egress_rejections: None,
        recorder_capture_diagnosis: None,
        response_diagnosis: None,
        possible_causes: Vec::new(),
        observed_target_fingerprint: "target".to_string(),
        attempt: 1,
        comparison_observation: None,
    });
    state.rule_plan = Some(RewriteRulePlanRecord {
        time: None,
        id: "plan-response".to_string(),
        issue_id: "issue-response".to_string(),
        kind: "uuid".to_string(),
        json_pointer: "/request_id".to_string(),
        source_evidence: Some("src/id.rs:new".to_string()),
        source_example: None,
        target_example: None,
        separator: None,
        response_body: None,
        jwt: None,
        evidence_id: "evidence-response".to_string(),
    });
    state
}

#[test]
fn persisted_response_plan_remains_applicable_after_revision_bump() {
    let mut state = response_state();
    state.bump();

    let record = pending_plan_for_apply(&state, "plan-response").unwrap();

    assert_eq!(record.evidence_id, "evidence-response");
}

#[test]
fn response_apply_does_not_revalidate_revision_scoped_evidence() {
    let mut state = response_state();
    state.bump();

    let error = apply(Path::new("/missing-target"), &mut state, "plan-response").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("requires a finalized case source")
    );
}

#[test]
fn pending_response_evidence_can_replace_preview() {
    let mut state = response_state();
    state.bump();

    validate_plan_evidence(
        Path::new("/missing-target"),
        &state,
        "issue-response",
        "evidence-response",
    )
    .unwrap();
}
