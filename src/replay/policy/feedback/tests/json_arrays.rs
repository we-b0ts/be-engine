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
            mode: Default::default(),
            format: crate::ResponseTimestampFormat::UnixSeconds,
        }),
        ResponseRuleKind::Duration => Some(crate::ResponseTimeRule::Duration {
            unit: crate::ResponseDurationUnit::Seconds,
        }),
        _ => None,
    };
    feedback.json_pointers = vec!["/data/*/value".into()];
    if feedback.time.is_some() {
        write_time_observations(root, &feedback);
    }
    feedback
}

fn write_time_observations(root: &Path, feedback: &ResponseRuleFeedback) {
    let request = root.join("request.json");
    let expected = root.join("expected.json");
    let actual = root.join("actual.json");
    fs::write(
        &request,
        r#"{"method":"GET","uri":"/api/resource/token","timestamp":"2023-11-14T22:13:20Z"}"#,
    )
    .unwrap();
    let (source, target) = if feedback.kind == ResponseRuleKind::Timestamp {
        ("1700000000", "1700000060")
    } else {
        ("120", "180")
    };
    for (path, value) in [(&expected, source), (&actual, target)] {
        fs::write(path, serde_json::to_vec(&json!({"version":1,"status":200,"headers":{},"request_sent_at":"2023-11-14T22:14:20Z","body":{"encoding":"utf8","truncated":false,"data":json!({"data":[{"value":value},{"value":value}]}).to_string()}})).unwrap()).unwrap();
    }
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
    let response = &mut evidence["cases"][0]["response"];
    response["request_path"] = json!(request);
    response["expected_response_path"] = json!(expected);
    response["actual_response_path"] = json!(actual);
    response["expected_response_fingerprint"] = json!(fingerprint(&fs::read(expected).unwrap()));
    response["actual_response_fingerprint"] = json!(fingerprint(&fs::read(actual).unwrap()));
    fs::write(
        &feedback.assertion_report,
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
}

fn relative_feedback(root: &Path, target_expiry: &str) -> ResponseRuleFeedback {
    let mut feedback = array_feedback(root, ResponseRuleKind::Timestamp);
    feedback.time = Some(crate::ResponseTimeRule::Timestamp {
        format: crate::ResponseTimestampFormat::Rfc3339,
        mode: crate::ResponseTimestampMode::PreserveRelative,
    });
    feedback.source_example = Some("2023-11-14T23:13:20Z".into());
    feedback.target_example = Some(target_expiry.into());
    for (name, expiry) in [
        ("expected.json", "2023-11-14T23:13:20Z"),
        ("actual.json", target_expiry),
    ] {
        let path = root.join(name);
        let mut response: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        response["body"]["data"] =
            json!(json!({"data":[{"value":expiry},{"value":expiry}]}).to_string());
        fs::write(path, serde_json::to_vec(&response).unwrap()).unwrap();
    }
    refresh_relative_fingerprints(root, &feedback);
    feedback
}

fn refresh_relative_fingerprints(root: &Path, feedback: &ResponseRuleFeedback) {
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
    evidence["cases"][0]["response"]["expected_response_fingerprint"] =
        json!(fingerprint(&fs::read(root.join("expected.json")).unwrap()));
    evidence["cases"][0]["response"]["actual_response_fingerprint"] =
        json!(fingerprint(&fs::read(root.join("actual.json")).unwrap()));
    fs::write(
        &feedback.assertion_report,
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
}

#[test]
fn relative_timestamp_plan_apply_persists_mode_and_replays_with_captured_clocks() {
    let temp = tempdir().unwrap();
    let feedback = relative_feedback(temp.path(), "2023-11-14T23:14:20Z");
    let source = fs::read(temp.path().join("expected.json")).unwrap();
    let target = fs::read(temp.path().join("actual.json")).unwrap();
    let plan = plan_response_rule(feedback.clone()).unwrap();
    plan.apply().unwrap();
    let policy = fs::read_to_string(&feedback.policy_path).unwrap();
    assert!(policy.contains("time: preserve_relative"));
    let report = crate::assert_recorded_response(crate::ResponseAssertionOptions {
        case_id: "case-1".into(),
        request: temp.path().join("request.json"),
        expected_response: temp.path().join("expected.json"),
        actual_response: temp.path().join("actual.json"),
        policy: feedback.policy_path,
    })
    .unwrap();
    assert!(report.passed, "{report:?}");
    assert_eq!(report.applied_generated_rule_ids.len(), 1);
    assert_eq!(fs::read(temp.path().join("expected.json")).unwrap(), source);
    assert_eq!(fs::read(temp.path().join("actual.json")).unwrap(), target);
}

#[test]
fn relative_timestamp_preflight_rejects_wrong_ttl_invalid_values_and_missing_clock() {
    for (expiry, missing_clock, constraint) in [
        ("2023-11-14T23:44:20Z", false, "DurationDeltaMismatch"),
        ("invalid", false, "TimeFieldInvalid"),
        ("2023-11-14T23:14:20Z", true, "TimeReferenceMissing"),
    ] {
        let temp = tempdir().unwrap();
        let feedback = relative_feedback(temp.path(), expiry);
        let policy = fs::read(&feedback.policy_path).unwrap();
        if missing_clock {
            let path = temp.path().join("actual.json");
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value.as_object_mut().unwrap().remove("request_sent_at");
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            refresh_relative_fingerprints(temp.path(), &feedback);
        }
        let error = plan_response_rule(feedback.clone())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(constraint), "{error}");
        assert_eq!(fs::read(&feedback.policy_path).unwrap(), policy);
    }
}

#[test]
fn relative_timestamp_apply_rejects_changed_response_witnesses() {
    let temp = tempdir().unwrap();
    let feedback = relative_feedback(temp.path(), "2023-11-14T23:14:20Z");
    let policy = fs::read(&feedback.policy_path).unwrap();
    let plan = plan_response_rule(feedback.clone()).unwrap();
    fs::write(temp.path().join("actual.json"), b"changed response").unwrap();
    assert!(plan.apply().is_err());
    assert_eq!(fs::read(&feedback.policy_path).unwrap(), policy);
}

#[test]
fn time_planning_rejects_unsatisfiable_timestamps_before_policy_mutation() {
    let temp = tempdir().unwrap();
    let feedback = array_feedback(temp.path(), ResponseRuleKind::Timestamp);
    let policy = fs::read(&feedback.policy_path).unwrap();
    let actual = temp.path().join("actual.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&actual).unwrap()).unwrap();
    value["body"]["data"] =
        json!(json!({"data":[{"value":"1700000660"},{"value":"1700000060"}]}).to_string());
    fs::write(&actual, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
    evidence["cases"][0]["response"]["actual_response_fingerprint"] =
        json!(fingerprint(&fs::read(&actual).unwrap()));
    fs::write(
        &feedback.assertion_report,
        serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
    let error = plan_response_rule(feedback.clone())
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("TimestampOutsideRequestWindow") && error.contains("/data/0/value"),
        "{error}"
    );
    assert_eq!(fs::read(&feedback.policy_path).unwrap(), policy);
}

#[test]
fn time_plans_freeze_response_evidence_and_require_captured_clocks() {
    for defect in ["before_plan", "after_plan", "missing_clock"] {
        let temp = tempdir().unwrap();
        let feedback = array_feedback(temp.path(), ResponseRuleKind::Duration);
        let policy = fs::read(&feedback.policy_path).unwrap();
        let actual = temp.path().join("actual.json");
        let plan = if defect == "after_plan" {
            Some(plan_response_rule(feedback.clone()).unwrap())
        } else {
            None
        };
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&actual).unwrap()).unwrap();
        if defect == "missing_clock" {
            value.as_object_mut().unwrap().remove("request_sent_at");
        } else {
            value["status"] = json!(201);
        }
        fs::write(&actual, serde_json::to_vec(&value).unwrap()).unwrap();
        if defect == "missing_clock" {
            let mut evidence: serde_json::Value =
                serde_json::from_slice(&fs::read(&feedback.assertion_report).unwrap()).unwrap();
            evidence["cases"][0]["response"]["actual_response_fingerprint"] =
                json!(fingerprint(&fs::read(&actual).unwrap()));
            fs::write(
                &feedback.assertion_report,
                serde_json::to_vec(&evidence).unwrap(),
            )
            .unwrap();
        }
        if let Some(plan) = plan {
            assert!(plan.apply().is_err());
        } else {
            assert!(plan_response_rule(feedback.clone()).is_err(), "{defect}");
        }
        assert_eq!(fs::read(&feedback.policy_path).unwrap(), policy);
    }
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
