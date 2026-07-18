use serde_json::json;
use tempfile::tempdir;

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
        assertion_report: assertions,
        aggregate_report: aggregate,
    };

    let plan = plan_response_rule(feedback).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().matching_cases, 1);
    let applied = plan.apply().unwrap();
    assert!(applied.applied);
    let updated = fs::read_to_string(&policy).unwrap();
    assert!(updated.contains("GET /api/resource/token"));
    assert!(updated.contains("/content"));
    validate_replay_policy(&policy).unwrap();
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
