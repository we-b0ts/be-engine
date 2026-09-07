use super::*;

fn array_feedback(root: &Path, kind: ResponseRuleKind) -> ResponseRuleFeedback {
    let mut feedback = write_generated_replay_feedback(
        root,
        json!([{
            "case_id": "case-1",
            "response": {
                "method": "GET", "path": "/api/resource/token", "body_codec": "json",
                "differences": [
                    {"pointer": "/data/0/value", "kind": "value_mismatch", "expected_type": "string", "actual_type": "string"},
                    {"pointer": "/data/1/value", "kind": "value_mismatch", "expected_type": "string", "actual_type": "string"}
                ],
                "generated_scalar_candidates": ["/data/0/value", "/data/1/value"]
            }
        }]),
        json!(["case-1"]),
        true,
        false,
    );
    feedback.kind = kind;
    feedback.time = match kind {
        ResponseRuleKind::Timestamp => Some(crate::ResponseTimeRule::Timestamp {
            format: crate::ResponseTimestampFormat::UnixSeconds,
        }),
        ResponseRuleKind::Duration => Some(crate::ResponseTimeRule::Duration {
            unit: crate::ResponseDurationUnit::Seconds,
        }),
        _ => None,
    };
    feedback.json_pointers = vec!["/data/*/value".into()];
    feedback
}

#[test]
fn array_generated_rules_plan_apply_and_compare_with_one_persisted_selector() {
    for kind in [
        ResponseRuleKind::Timestamp,
        ResponseRuleKind::Duration,
        ResponseRuleKind::Uuid,
        ResponseRuleKind::Random,
    ] {
        let temp = tempdir().unwrap();
        let feedback = array_feedback(temp.path(), kind);
        let policy = feedback.policy_path.clone();
        let plan = plan_response_rule(feedback).unwrap();
        assert_eq!(plan.report().json_pointers, ["/data/*/value"]);
        assert_eq!(plan.report().selected_difference_cases, 1);
        assert_eq!(plan.report().residual_difference_cases, 0);
        plan.apply().unwrap();
        let persisted = fs::read_to_string(&policy).unwrap();
        assert!(persisted.contains("pointer: /data/*/value"));
        assert!(!persisted.contains("/data/0/value"));

        let request = temp.path().join("request.json");
        let expected = temp.path().join("expected.json");
        let actual = temp.path().join("actual.json");
        fs::write(
            &request,
            r#"{"method":"GET","uri":"/api/resource/token","timestamp":"2023-11-14T22:13:20Z"}"#,
        )
        .unwrap();
        let (source, target) = match kind {
            ResponseRuleKind::Timestamp => ("1700000000", "1700000060"),
            ResponseRuleKind::Duration => ("120", "180"),
            _ => ("source", "target"),
        };
        for (path, value) in [(&expected, source), (&actual, target)] {
            fs::write(path, serde_json::to_vec(&json!({
                "version": 1, "request_sent_at": "2023-11-14T22:14:20Z", "status": 200, "body": {"encoding": "utf8", "truncated": false,
                    "data": json!({"data": [{"value": value}, {"value": value}, {"value": value}]}).to_string()}
            })).unwrap()).unwrap();
        }
        let report =
            crate::replay::assert_recorded_response(crate::replay::ResponseAssertionOptions {
                case_id: "case-1".into(),
                request,
                expected_response: expected,
                actual_response: actual,
                policy,
            })
            .unwrap();
        assert!(report.passed, "{report:?}");
        assert_eq!(report.applied_generated_rule_ids.len(), 1);
    }
}

#[test]
fn array_rule_planner_rejects_structural_differences_in_any_selected_element() {
    for (pointer, kind, expected_type, actual_type) in [
        ("/data/1/value", "missing_actual", Some("string"), None),
        (
            "/data/1/value",
            "type_mismatch",
            Some("string"),
            Some("number"),
        ),
        (
            "/data",
            "array_length_mismatch",
            Some("array"),
            Some("array"),
        ),
    ] {
        let temp = tempdir().unwrap();
        let feedback = array_feedback(temp.path(), ResponseRuleKind::Duration);
        let mut evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
        evidence["cases"][0]["response"]["differences"][1] = json!({
            "pointer": pointer, "kind": kind, "expected_type": expected_type, "actual_type": actual_type
        });
        fs::write(
            &feedback.assertion_report,
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        let error = plan_response_rule(feedback).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("unsupported response difference"),
            "{error}"
        );
    }
}

#[test]
fn comparison_array_rules_preserve_source_change_checks_and_counter_scope() {
    for (kind, source_changes, allowed) in [
        (ResponseRuleKind::Timestamp, json!([]), true),
        (ResponseRuleKind::Timestamp, json!(["/data/1/value"]), false),
        (ResponseRuleKind::Counter, json!(["/data/1/value"]), true),
    ] {
        let temp = tempdir().unwrap();
        let feedback = array_feedback(temp.path(), kind);
        let mut evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
        evidence["cases"][0]["source_change_pointers"] = source_changes;
        evidence["kind"] = json!("comparison_recording_verification");
        evidence["assertion_mode"] = json!("comparison_recording");
        evidence["baseline_recheck"] = json!("optional_source_consistency");
        evidence["complete"] = json!(true);
        fs::write(
            &feedback.assertion_report,
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        let result = plan_comparison_response_rule(ComparisonResponseRuleFeedback {
            time: feedback.time,
            policy_path: feedback.policy_path,
            kind,
            api: feedback.api,
            json_pointers: feedback.json_pointers,
            source_evidence: feedback.source_evidence,
            source_example: feedback.source_example,
            target_example: feedback.target_example,
            separator: None,
            comparison_report: feedback.assertion_report,
        });
        if allowed {
            result.unwrap().apply().unwrap();
        } else {
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("source changes overlapping")
            );
        }
    }
}

#[test]
fn array_rule_planner_preserves_unselected_differences() {
    let temp = tempdir().unwrap();
    let feedback = array_feedback(temp.path(), ResponseRuleKind::Random);
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
    evidence["cases"][0]["response"]["differences"][1]["pointer"] = json!("/data/1/stable");
    fs::write(
        &feedback.assertion_report,
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
    let plan = plan_response_rule(feedback).unwrap();
    assert_eq!(plan.report().residual_difference_cases, 1);
    assert_eq!(
        plan.report().unselected_difference_pointers,
        ["/data/1/stable"]
    );
}

#[test]
fn joined_string_array_rules_require_matching_evidence_for_every_difference() {
    for second_separator in [",", ";"] {
        let temp = tempdir().unwrap();
        let mut feedback = array_feedback(temp.path(), ResponseRuleKind::UnorderedJoinedString);
        feedback.source_example = None;
        feedback.target_example = None;
        feedback.separator = Some(",".into());
        let mut evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
        evidence["cases"][0]["response"]["unordered_joined_string_candidates"] = json!([
            {"pointer": "/data/0/value", "separator": ","},
            {"pointer": "/data/1/value", "separator": second_separator}
        ]);
        fs::write(
            &feedback.assertion_report,
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        let result = plan_response_rule(feedback);
        if second_separator == "," {
            result.unwrap().apply().unwrap();
        } else {
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("joined-string evidence")
            );
        }
    }
}
