use std::path::Path;

use serde_json::json;
use tempfile::tempdir;

use super::evidence::{AssertionCaseEvidence, DifferenceEvidence, source_change_overlaps};
use super::*;
use crate::replay::validate_replay_policy;

#[test]
fn plans_and_applies_evidence_backed_dynamic_field() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_mode": "json_structural",
                    "differences": [{
                        "pointer": "/content",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }],
                    "applied_dynamic_rule_ids": [],
                    "dynamic_candidates": ["/content"]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "selected_case_ids": ["case-1"],
            "complete": true,
            "dirty": false
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ResponseRuleFeedback {
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Dynamic,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        dynamic_mechanisms: vec![DynamicResponseMechanism::Uuid],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        assertion_report: assertions,
        aggregate_report: aggregate,
    };

    let plan = plan_response_rule(feedback).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().matching_cases, 1);
    assert_eq!(
        plan.report().dynamic_mechanisms,
        vec![DynamicResponseMechanism::Uuid]
    );
    assert_eq!(
        plan.report().source_evidence.as_deref(),
        Some("src/token.rs:issue_token")
    );
    assert_eq!(
        plan.report().source_example.as_deref(),
        Some("<redacted source UUID>")
    );
    assert_eq!(
        plan.report().target_example.as_deref(),
        Some("<redacted target UUID>")
    );
    let applied = plan.apply().unwrap();
    assert!(applied.applied);
    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("GET /api/resource/token"));
    assert!(updated.contains("pointer: /content"));
    assert!(updated.contains("mechanisms:"));
    assert!(updated.contains("- uuid"));
    assert!(updated.contains("source_evidence: src/token.rs:issue_token"));
    assert!(updated.contains("source_example: <redacted source UUID>"));
    assert!(updated.contains("target_example: <redacted target UUID>"));
    validate_replay_policy(&policy).unwrap();
}

#[test]
fn replay_rule_planning_resolves_runner_owned_assertion_details() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    let detail = temp.path().join("assertion-detail.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &detail,
        serde_json::to_vec(&json!({
            "method": "GET",
            "path": "/api/resource/token",
            "body_mode": "json_structural",
            "differences": [{
                "pointer": "/content",
                "kind": "value_mismatch",
                "expected_type": "string",
                "actual_type": "string"
            }],
            "dynamic_candidates": ["/content"]
        }))
        .unwrap(),
    )
    .unwrap();
    let detail_fingerprint = crate::replay::policy::fingerprint(&fs::read(&detail).unwrap());
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "passed": false,
                    "difference_count": 1,
                    "detail_report": detail,
                    "detail_fingerprint": detail_fingerprint
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "selected_case_ids": ["case-1"],
            "complete": true,
            "dirty": false
        }))
        .unwrap(),
    )
    .unwrap();

    let plan = plan_response_rule(ResponseRuleFeedback {
        policy_path: policy,
        kind: ResponseRuleKind::Dynamic,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        dynamic_mechanisms: vec![DynamicResponseMechanism::Uuid],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        assertion_report: assertions,
        aggregate_report: aggregate,
    })
    .unwrap();

    assert!(plan.report().changed);
    assert_eq!(plan.report().selected_difference_cases, 1);
}

#[test]
fn dynamic_field_plan_preserves_unselected_differences_and_dirty_dependencies() {
    let temp = tempdir().unwrap();
    let feedback = write_dynamic_replay_feedback(
        temp.path(),
        json!([
            {
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_mode": "json_structural",
                    "differences": [
                        {
                            "pointer": "/content",
                            "kind": "value_mismatch",
                            "expected_type": "string",
                            "actual_type": "string"
                        },
                        {
                            "pointer": "/avatar",
                            "kind": "value_mismatch",
                            "expected_type": "string",
                            "actual_type": "string"
                        },
                        {
                            "pointer": "/stable_count",
                            "kind": "value_mismatch",
                            "expected_type": "number",
                            "actual_type": "number"
                        }
                    ],
                    "applied_dynamic_rule_ids": [],
                    "dynamic_candidates": ["/content", "/avatar"]
                }
            },
            {
                "case_id": "case-2",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_mode": "json_structural",
                    "differences": [{
                        "pointer": "/stable_count",
                        "kind": "value_mismatch",
                        "expected_type": "number",
                        "actual_type": "number"
                    }],
                    "applied_dynamic_rule_ids": [],
                    "dynamic_candidates": []
                }
            }
        ]),
        json!(["case-1", "case-2"]),
        true,
        true,
    );

    let plan = plan_response_rule(feedback).unwrap();
    assert_eq!(plan.report().matching_cases, 2);
    assert_eq!(plan.report().selected_difference_cases, 1);
    assert_eq!(plan.report().aggregate_dirty, Some(true));
    assert_eq!(
        plan.report().unselected_difference_pointers,
        vec!["/avatar".to_string(), "/stable_count".to_string()]
    );

    plan.apply().unwrap();
    let updated = fs::read_to_string(temp.path().join("replay.yaml")).unwrap();
    assert!(updated.contains("pointer: /content"));
    assert!(!updated.contains("pointer: /avatar"));
    assert!(!updated.contains("pointer: /stable_count"));
}

#[test]
fn dynamic_field_plan_still_requires_complete_aggregate_evidence() {
    let temp = tempdir().unwrap();
    let feedback = write_dynamic_replay_feedback(
        temp.path(),
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET",
                "path": "/api/resource/token",
                "body_mode": "json_structural",
                "differences": [{
                    "pointer": "/content",
                    "kind": "value_mismatch",
                    "expected_type": "string",
                    "actual_type": "string"
                }],
                "applied_dynamic_rule_ids": [],
                "dynamic_candidates": ["/content"]
            }
        }]),
        json!(["case-1"]),
        false,
        false,
    );

    let error = plan_response_rule(feedback)
        .err()
        .expect("incomplete replay evidence must not authorize a response rule");
    assert_eq!(
        error.to_string(),
        "aggregate replay evidence must be complete"
    );
}

#[test]
fn dynamic_field_plan_rejects_structural_differences_at_selected_location() {
    let temp = tempdir().unwrap();
    let feedback = write_dynamic_replay_feedback(
        temp.path(),
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET",
                "path": "/api/resource/token",
                "body_mode": "json_structural",
                "differences": [{
                    "pointer": "/content/value",
                    "kind": "value_mismatch",
                    "expected_type": "string",
                    "actual_type": "string"
                }],
                "applied_dynamic_rule_ids": [],
                "dynamic_candidates": ["/content"]
            }
        }]),
        json!(["case-1"]),
        true,
        false,
    );

    let error = plan_response_rule(feedback)
        .err()
        .expect("a parent dynamic rule must not cover a child difference");
    assert!(
        error
            .to_string()
            .contains("unsupported response difference at selected location /content/value")
    );
}

#[test]
fn plans_and_applies_dynamic_field_from_comparison_recording_evidence() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let comparison = temp.path().join("comparison-report.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &comparison,
        serde_json::to_vec(&json!({
            "version": 4,
            "kind": "comparison_recording_verification",
            "expected_response": "assertions_only",
            "assertion_mode": "comparison_recording",
            "baseline_recheck": "optional_source_consistency",
            "policy_fingerprint": fingerprint,
            "complete": true,
            "cases": [{
                "case_id": "case-1",
                "classification": "candidate_difference",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_mode": "json_structural",
                    "differences": [{
                        "pointer": "/content",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }],
                    "applied_dynamic_rule_ids": [],
                    "dynamic_candidates": ["/content"]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ComparisonResponseRuleFeedback {
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Dynamic,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        dynamic_mechanisms: vec![DynamicResponseMechanism::Uuid],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        comparison_report: comparison,
    };

    let plan = plan_comparison_response_rule(feedback).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().matching_cases, 1);
    assert!(plan.report().comparison_report.is_some());
    assert!(plan.report().assertion_report.is_none());
    plan.apply().unwrap();
    assert!(fs::read_to_string(policy).unwrap().contains("/content"));
}

#[test]
fn plans_and_applies_comparison_only_counter_fields() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("verification.yaml");
    let comparison = temp.path().join("comparison-report.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\nresponse_rules:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &comparison,
        serde_json::to_vec(&json!({
            "version": 3,
            "kind": "comparison_recording_verification",
            "expected_response": "assertions_only",
            "assertion_mode": "comparison_recording",
            "baseline_recheck": "optional_source_consistency",
            "policy_fingerprint": fingerprint,
            "complete": true,
            "cases": [{
                "case_id": "case-1",
                "classification": "source_change",
                "source_change_pointers": ["/followers_count"],
                "response": {
                    "method": "GET",
                    "path": "/api/users/show",
                    "body_mode": "json_structural",
                    "differences": [{
                        "pointer": "/followers_count",
                        "kind": "value_mismatch",
                        "expected_type": "number",
                        "actual_type": "number"
                    }],
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ComparisonResponseRuleFeedback {
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Counter,
        api: "GET /api/users/show".to_string(),
        json_pointers: vec!["/followers_count".to_string()],
        dynamic_mechanisms: vec![],
        source_evidence: Some("src/user.rs:load live follower count".to_string()),
        source_example: Some("100".to_string()),
        target_example: Some("101".to_string()),
        comparison_report: comparison,
    };

    let plan = plan_comparison_response_rule(feedback).unwrap();

    assert!(plan.report().changed);
    assert_eq!(plan.report().kind, ResponseRuleKind::Counter);
    assert_eq!(
        plan.report().added_rule_ids,
        ["response:comparison:counter:GET /api/users/show:/followers_count"]
    );
    plan.apply().unwrap();
    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("comparison:"));
    assert!(updated.contains("source_match: before_or_after"));
    assert!(updated.contains("counter:"));
    assert!(updated.contains("src/user.rs:load live follower count"));
    let report = validate_replay_policy(&policy).unwrap();
    assert_eq!(
        report.comparison.source_match,
        crate::replay::ComparisonSourceMatch::BeforeOrAfter
    );
}

#[test]
fn a_permitted_source_after_match_does_not_authorize_a_response_rule() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("verification.yaml");
    let comparison = temp.path().join("comparison-report.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\nresponse_rules:\n  comparison:\n    source_match: before_or_after\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &comparison,
        serde_json::to_vec(&json!({
            "version": 4,
            "kind": "comparison_recording_verification",
            "expected_response": "assertions_only",
            "assertion_mode": "comparison_recording",
            "baseline_recheck": "optional_source_consistency",
            "policy_fingerprint": fingerprint,
            "complete": true,
            "cases": [{
                "case_id": "case-1",
                "classification": "passed",
                "matched_source": "after",
                "response": {
                    "method": "GET",
                    "path": "/api/users/show",
                    "body_mode": "json_structural",
                    "differences": [{
                        "pointer": "/followers_count",
                        "kind": "value_mismatch",
                        "expected_type": "number",
                        "actual_type": "number"
                    }]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ComparisonResponseRuleFeedback {
        policy_path: policy,
        kind: ResponseRuleKind::Counter,
        api: "GET /api/users/show".to_string(),
        json_pointers: vec!["/followers_count".to_string()],
        dynamic_mechanisms: vec![],
        source_evidence: Some("src/user.rs:load live follower count".to_string()),
        source_example: Some("100".to_string()),
        target_example: Some("101".to_string()),
        comparison_report: comparison,
    };

    let error = plan_comparison_response_rule(feedback)
        .err()
        .expect("source-after match must not authorize a response rule");

    assert!(
        error
            .to_string()
            .contains("already matches the permitted source-after observation")
    );
}

#[test]
fn plans_and_applies_evidence_backed_unordered_array() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/config/ansible_facts",
                    "body_mode": "json_structural",
                    "differences": [{
                        "pointer": "/general/sudo_users",
                        "kind": "array_order_mismatch",
                        "expected_type": "array",
                        "actual_type": "array"
                    }],
                    "applied_unordered_rule_ids": [],
                    "unordered_candidates": ["/general/sudo_users"]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "selected_case_ids": ["case-1"],
            "complete": true,
            "dirty": false
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ResponseRuleFeedback {
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Unordered,
        api: "GET /api/config/ansible_facts".to_string(),
        json_pointers: vec!["/general/sudo_users".to_string()],
        dynamic_mechanisms: vec![],
        source_evidence: None,
        source_example: None,
        target_example: None,
        assertion_report: assertions,
        aggregate_report: aggregate,
    };

    let plan = plan_response_rule(feedback).unwrap();
    assert_eq!(plan.report().kind, ResponseRuleKind::Unordered);
    assert_eq!(
        plan.report().added_rule_ids,
        vec!["response:unordered:GET /api/config/ansible_facts:/general/sudo_users".to_string()]
    );
    let applied = plan.apply().unwrap();
    assert!(applied.applied);
    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("unordered:"));
    assert!(updated.contains("/general/sudo_users"));
    validate_replay_policy(&policy).unwrap();
}

#[test]
fn unordered_evidence_rejects_content_differences() {
    let requested = BTreeSet::from(["/content".to_string()]);
    let content_difference = DifferenceEvidence {
        pointer: "/content".to_string(),
        kind: "value_mismatch".to_string(),
        expected_type: Some("string".to_string()),
        actual_type: Some("string".to_string()),
    };
    let wrong_array = DifferenceEvidence {
        pointer: "/other".to_string(),
        kind: "array_order_mismatch".to_string(),
        expected_type: Some("array".to_string()),
        actual_type: Some("array".to_string()),
    };

    assert!(!difference_supports_rule(
        ResponseRuleKind::Unordered,
        &content_difference,
        &requested
    ));
    assert!(!difference_supports_rule(
        ResponseRuleKind::Unordered,
        &wrong_array,
        &requested
    ));
}

#[test]
fn dynamic_rule_requires_auditable_mechanism_evidence() {
    let error = justification::validate(ResponseRuleKind::Dynamic, vec![], None, None, None)
        .err()
        .expect("missing dynamic evidence must fail");
    assert!(
        error
            .to_string()
            .contains("at least one --dynamic-mechanism")
    );

    let justification = justification::validate(
        ResponseRuleKind::Dynamic,
        vec![
            DynamicResponseMechanism::DynamicDerived,
            DynamicResponseMechanism::Timestamp,
        ],
        Some("src/signed_url.rs:sign".to_string()),
        Some("https://img.test/a?Expires=<source-time>&ssig=<source-signature>".to_string()),
        Some("https://img.test/a?Expires=<target-time>&ssig=<target-signature>".to_string()),
    )
    .unwrap();
    assert_eq!(justification.dynamic_mechanisms.len(), 2);
}

#[test]
fn one_evidence_bundle_can_cover_multiple_dynamic_fields() {
    let temp = tempdir().unwrap();
    let mut feedback = write_dynamic_replay_feedback(
        temp.path(),
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET",
                "path": "/api/resource/token",
                "body_mode": "json_structural",
                "differences": [
                    {
                        "pointer": "/first",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    },
                    {
                        "pointer": "/second",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }
                ],
                "dynamic_candidates": ["/first", "/second"]
            }
        }]),
        json!(["case-1"]),
        true,
        false,
    );
    feedback.json_pointers = vec!["/first".to_string(), "/second".to_string()];

    let plan = plan_response_rule(feedback).unwrap();

    assert_eq!(plan.report().json_pointers, ["/first", "/second"]);
    assert_eq!(plan.report().added_rule_ids.len(), 2);
}

#[test]
fn source_change_can_block_only_an_overlapping_response_rule() {
    let case = AssertionCaseEvidence {
        case_id: "case-1".to_string(),
        classification: Some("candidate_difference".to_string()),
        matched_source: None,
        source_change_pointers: vec!["/profile/avatar".to_string()],
        policy_mismatch_rule_ids: Vec::new(),
        response: None,
    };

    assert!(source_change_overlaps(
        &case,
        &BTreeSet::from(["/profile".to_string()])
    ));
    assert!(!source_change_overlaps(
        &case,
        &BTreeSet::from(["/counts/followers".to_string()])
    ));
}

fn write_dynamic_replay_feedback(
    root: &Path,
    cases: serde_json::Value,
    selected_case_ids: serde_json::Value,
    complete: bool,
    dirty: bool,
) -> ResponseRuleFeedback {
    let policy = root.join("replay.yaml");
    let assertions = root.join("assertions.json");
    let aggregate = root.join("aggregate.json");
    fs::write(
        &policy,
        "version: 2\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": cases
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({
            "case_source": "/cases",
            "selected_case_ids": selected_case_ids,
            "complete": complete,
            "dirty": dirty
        }))
        .unwrap(),
    )
    .unwrap();
    ResponseRuleFeedback {
        policy_path: policy,
        kind: ResponseRuleKind::Dynamic,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        dynamic_mechanisms: vec![DynamicResponseMechanism::Uuid],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        assertion_report: assertions,
        aggregate_report: aggregate,
    }
}
