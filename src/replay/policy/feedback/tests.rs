use std::path::Path;

use serde_json::json;
use tempfile::tempdir;

use super::evidence::{AssertionCaseEvidence, DifferenceEvidence, source_change_overlaps};
use super::*;
use crate::replay::validate_replay_policy;

#[path = "tests/json_arrays.rs"]
mod json_arrays;

#[test]
fn plans_and_applies_evidence_backed_uuid_field() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "version": 3,
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/content",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }],
                    "applied_generated_rule_ids": [],
                    "generated_scalar_candidates": ["/content"]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &aggregate,
        serde_json::to_vec(&json!({
            "version": 3,
            "case_source": "/cases",
            "selected_case_ids": ["case-1"],
            "complete": true,
            "dirty": false
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ResponseRuleFeedback {
        time: None,
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Uuid,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        separator: None,
        assertion_report: assertions,
        aggregate_report: aggregate,
    };

    let plan = plan_response_rule(feedback).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().matching_cases, 1);
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
    assert!(updated.contains("uuid:"));
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
    let stale_detail = temp
        .path()
        .join("focused/api-1/.active/reports/assertion-detail.json");
    let published_detail = temp
        .path()
        .join("focused/api-1/latest/reports/assertion-detail.json");
    fs::create_dir_all(published_detail.parent().unwrap()).unwrap();
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &published_detail,
        serde_json::to_vec(&json!({
            "method": "GET",
            "path": "/api/resource/token",
            "body_codec": "json",
            "differences": [{
                "pointer": "/content",
                "kind": "value_mismatch",
                "expected_type": "string",
                "actual_type": "string"
            }],
            "generated_scalar_candidates": ["/content"]
        }))
        .unwrap(),
    )
    .unwrap();
    let detail_fingerprint =
        crate::replay::policy::fingerprint(&fs::read(&published_detail).unwrap());
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "version": 3,
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "passed": false,
                    "difference_count": 1,
                    "detail_report": stale_detail,
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
            "version": 3,
            "case_source": "/cases",
            "selected_case_ids": ["case-1"],
            "complete": true,
            "dirty": false
        }))
        .unwrap(),
    )
    .unwrap();

    let plan = plan_response_rule(ResponseRuleFeedback {
        time: None,
        policy_path: policy,
        kind: ResponseRuleKind::Uuid,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        separator: None,
        assertion_report: assertions,
        aggregate_report: aggregate,
    })
    .unwrap();

    assert!(plan.report().changed);
    assert_eq!(plan.report().selected_difference_cases, 1);
}

#[test]
fn generated_field_plan_preserves_unselected_differences_and_dirty_dependencies() {
    let temp = tempdir().unwrap();
    let feedback = write_generated_replay_feedback(
        temp.path(),
        json!([
            {
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
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
                    "applied_generated_rule_ids": [],
                    "generated_scalar_candidates": ["/content", "/avatar"]
                }
            },
            {
                "case_id": "case-2",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/stable_count",
                        "kind": "value_mismatch",
                        "expected_type": "number",
                        "actual_type": "number"
                    }],
                    "applied_generated_rule_ids": [],
                    "generated_scalar_candidates": []
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
fn unordered_plan_preserves_unselected_differences_and_dirty_dependencies() {
    let temp = tempdir().unwrap();
    let mut feedback = write_generated_replay_feedback(
        temp.path(),
        json!([
            {
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
                    "differences": [
                        {
                            "pointer": "/members",
                            "kind": "array_order_mismatch",
                            "expected_type": "array",
                            "actual_type": "array"
                        },
                        {
                            "pointer": "/source",
                            "kind": "value_mismatch",
                            "expected_type": "string",
                            "actual_type": "string"
                        }
                    ],
                    "unordered_candidates": ["/members"]
                }
            },
            {
                "case_id": "case-2",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/source",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }]
                }
            }
        ]),
        json!(["case-1", "case-2"]),
        true,
        true,
    );
    feedback.kind = ResponseRuleKind::Unordered;
    feedback.json_pointers = vec!["/members".to_string()];
    feedback.source_evidence =
        Some("src/members.rs:42-48 MemberService::members returns a Set".to_string());
    feedback.source_example = None;
    feedback.target_example = None;

    let plan = plan_response_rule(feedback).unwrap();
    assert_eq!(plan.report().matching_cases, 2);
    assert_eq!(plan.report().selected_difference_cases, 1);
    assert_eq!(plan.report().residual_difference_cases, 2);
    assert_eq!(plan.report().aggregate_dirty, Some(true));
    assert_eq!(
        plan.report().unselected_difference_pointers,
        vec!["/source".to_string()]
    );

    plan.apply().unwrap();
    let updated = fs::read_to_string(temp.path().join("replay.yaml")).unwrap();
    assert!(updated.contains("unordered:"));
    assert!(updated.contains("pointer: /members"));
    assert!(!updated.contains("pointer: /source"));
}

#[test]
fn unordered_plan_rejects_a_real_difference_at_the_selected_location() {
    let temp = tempdir().unwrap();
    let mut feedback = write_generated_replay_feedback(
        temp.path(),
        json!([
            {
                "case_id": "case-order",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/members",
                        "kind": "array_order_mismatch",
                        "expected_type": "array",
                        "actual_type": "array"
                    }],
                    "unordered_candidates": ["/members"]
                }
            },
            {
                "case_id": "case-content",
                "response": {
                    "method": "GET",
                    "path": "/api/resource/token",
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/members",
                        "kind": "array_length_mismatch",
                        "expected_type": "array",
                        "actual_type": "array"
                    }]
                }
            }
        ]),
        json!(["case-order", "case-content"]),
        true,
        false,
    );
    feedback.kind = ResponseRuleKind::Unordered;
    feedback.json_pointers = vec!["/members".to_string()];
    feedback.source_evidence =
        Some("src/members.rs:42-48 MemberService::members returns a Set".to_string());
    feedback.source_example = None;
    feedback.target_example = None;

    let error = plan_response_rule(feedback).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("unsupported response difference at selected location /members")
    );
}

#[test]
fn generated_field_plan_still_requires_complete_aggregate_evidence() {
    let temp = tempdir().unwrap();
    let feedback = write_generated_replay_feedback(
        temp.path(),
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET",
                "path": "/api/resource/token",
                "body_codec": "json",
                "differences": [{
                    "pointer": "/content",
                    "kind": "value_mismatch",
                    "expected_type": "string",
                    "actual_type": "string"
                }],
                "applied_generated_rule_ids": [],
                "generated_scalar_candidates": ["/content"]
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
fn generated_field_plan_rejects_structural_differences_at_selected_location() {
    let temp = tempdir().unwrap();
    let feedback = write_generated_replay_feedback(
        temp.path(),
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET",
                "path": "/api/resource/token",
                "body_codec": "json",
                "differences": [{
                    "pointer": "/content/value",
                    "kind": "value_mismatch",
                    "expected_type": "string",
                    "actual_type": "string"
                }],
                "applied_generated_rule_ids": [],
                "generated_scalar_candidates": ["/content"]
            }
        }]),
        json!(["case-1"]),
        true,
        false,
    );

    let error = plan_response_rule(feedback)
        .err()
        .expect("a parent generated rule must not cover a child difference");
    assert!(
        error
            .to_string()
            .contains("unsupported response difference at selected location /content/value")
    );
}

#[test]
fn plans_and_applies_uuid_field_from_comparison_recording_evidence() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let comparison = temp.path().join("comparison-report.json");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
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
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/content",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }],
                    "applied_generated_rule_ids": [],
                    "generated_scalar_candidates": ["/content"]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = ComparisonResponseRuleFeedback {
        time: None,
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Uuid,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        separator: None,
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
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_settings:\n  comparison:\n    source_match: before_or_after\n",
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
                    "body_codec": "json",
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
        time: None,
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Counter,
        api: "GET /api/users/show".to_string(),
        json_pointers: vec!["/followers_count".to_string()],
        source_evidence: Some("src/user.rs:load live follower count".to_string()),
        source_example: Some("100".to_string()),
        target_example: Some("101".to_string()),
        separator: None,
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
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_settings:\n  comparison:\n    source_match: before_or_after\n",
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
                    "body_codec": "json",
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
        time: None,
        policy_path: policy,
        kind: ResponseRuleKind::Counter,
        api: "GET /api/users/show".to_string(),
        json_pointers: vec!["/followers_count".to_string()],
        source_evidence: Some("src/user.rs:load live follower count".to_string()),
        source_example: Some("100".to_string()),
        target_example: Some("101".to_string()),
        separator: None,
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
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "version": 3,
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/config/ansible_facts",
                    "body_codec": "json",
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
        time: None,
        policy_path: policy.clone(),
        kind: ResponseRuleKind::Unordered,
        api: "GET /api/config/ansible_facts".to_string(),
        json_pointers: vec!["/general/sudo_users".to_string()],
        source_evidence: Some("src/config.rs:sudo_users is a set".to_string()),
        source_example: None,
        target_example: None,
        separator: None,
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
    assert!(updated.contains("src/config.rs:sudo_users is a set"));
    validate_replay_policy(&policy).unwrap();
}

#[test]
fn plans_and_applies_separator_specific_joined_string_rule() {
    let temp = tempdir().unwrap();
    let policy = temp.path().join("replay.yaml");
    let assertions = temp.path().join("assertions.json");
    let aggregate = temp.path().join("aggregate.json");
    fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "version": 3,
            "case_source": "/cases",
            "expected_response": "assertions_only",
            "assertion_mode": "runner_owned",
            "policy_fingerprint": fingerprint,
            "cases": [{
                "case_id": "case-1",
                "response": {
                    "method": "GET",
                    "path": "/api/config/ansible_facts",
                    "body_codec": "json",
                    "differences": [{
                        "pointer": "/general/sudo_users",
                        "kind": "value_mismatch",
                        "expected_type": "string",
                        "actual_type": "string"
                    }],
                    "unordered_joined_string_candidates": [{
                        "pointer": "/general/sudo_users",
                        "separator": ","
                    }]
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
        time: None,
        policy_path: policy.clone(),
        kind: ResponseRuleKind::UnorderedJoinedString,
        api: "GET /api/config/ansible_facts".to_string(),
        json_pointers: vec!["/general/sudo_users".to_string()],
        source_evidence: Some("src/config.rs:sudo_users is set-joined".to_string()),
        source_example: None,
        target_example: None,
        separator: Some(",".to_string()),
        assertion_report: assertions,
        aggregate_report: aggregate,
    };

    let plan = plan_response_rule(feedback).unwrap();
    assert_eq!(
        plan.report().added_rule_ids,
        ["response:unordered_joined_string:GET /api/config/ansible_facts:/general/sudo_users"]
    );
    assert_eq!(plan.report().separator.as_deref(), Some(","));
    plan.apply().unwrap();
    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("unordered_joined_string:"));
    assert!(updated.contains("separator: ','"));
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
fn generated_rule_requires_auditable_source_evidence() {
    let error = justification::validate(ResponseRuleKind::Uuid, None, None, None, None, None)
        .err()
        .expect("missing UUID evidence must fail");
    assert!(error.to_string().contains("--source-evidence"));

    let justification = justification::validate(
        ResponseRuleKind::Random,
        None,
        Some("src/token.rs:generate uses a random nonce".to_string()),
        Some("<source random token>".to_string()),
        Some("<target random token>".to_string()),
        None,
    )
    .unwrap();
    assert!(justification.source_evidence.is_some());
}

#[test]
fn one_evidence_bundle_can_cover_multiple_generated_fields() {
    let temp = tempdir().unwrap();
    let mut feedback = write_generated_replay_feedback(
        temp.path(),
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET",
                "path": "/api/resource/token",
                "body_codec": "json",
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
                "generated_scalar_candidates": ["/first", "/second"]
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
        passed: false,
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

fn write_generated_replay_feedback(
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
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let fingerprint = validate_replay_policy(&policy).unwrap().fingerprint;
    fs::write(
        &assertions,
        serde_json::to_vec(&json!({
            "version": 3,
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
        time: None,
        policy_path: policy,
        kind: ResponseRuleKind::Uuid,
        api: "GET /api/resource/token".to_string(),
        json_pointers: vec!["/content".to_string()],
        source_evidence: Some("src/token.rs:issue_token".to_string()),
        source_example: Some("<redacted source UUID>".to_string()),
        target_example: Some("<redacted target UUID>".to_string()),
        separator: None,
        assertion_report: assertions,
        aggregate_report: aggregate,
    }
}
