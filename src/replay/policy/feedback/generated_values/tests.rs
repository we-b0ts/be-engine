use super::*;
use crate::replay::policy::feedback::tests::RetiredFixture;
use serde_json::json;
#[test]
fn retired_identity_and_header_date_planners_preserve_the_whole_policy() {
    let fixture = RetiredFixture::new();
    fixture.check(|| plan_dynamic_value_rule(fixture.identity()));
    let rule=serde_json::from_value(json!({"header":"content-disposition","parameter":"filename","format":"%Y-%m-%d","timezone":"+00:00","source_evidence":"src/export.rs creates a current UTC dated filename"})).unwrap();
    fixture.check(|| {
        plan_response_header_date_rule(ResponseHeaderDateRuleFeedback {
            policy_path: fixture.policy.clone(),
            api: "GET /download".into(),
            rules: vec![rule],
            evidence: ResponseBodyRuleEvidence::FocusedE2e {
                assertion_report: fixture.evidence.clone(),
                aggregate_report: fixture.evidence.clone(),
            },
        })
    });
}
#[test]
fn retired_pending_generated_plan_cannot_apply_after_an_upgrade() {
    let fixture = RetiredFixture::new();
    let plan = GeneratedValueRulePlan {
        policy_path: fixture.policy.clone(),
        original: fs::read_to_string(&fixture.policy).unwrap(),
        updated: "must never replace the unified policy".into(),
        witnesses: vec![],
        key_witnesses: vec![],
        report: GeneratedValueRuleReport {
            kind: "dynamic_value".into(),
            api: "GET /api".into(),
            policy_fingerprint: "old-plan".into(),
            matching_cases: 1,
            selected_difference_cases: 1,
            added_rule_ids: vec!["old".into()],
            changed: true,
            applied: false,
            requires_fresh_replay: true,
            diff: String::new(),
        },
    };
    fixture.check(|| plan.apply());
}
