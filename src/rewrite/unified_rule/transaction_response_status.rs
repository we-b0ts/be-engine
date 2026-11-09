//! Rule publication is independent of primary response status acceptance.
use super::*;

fn proposal(kind: &str) -> serde_json::Value {
    match kind {
        "json" => json!({"format":"traffic-policy/v3","json":{"fields":{
            "/id":{"kind":"identity","formats":["uuid"]}
        }}}),
        "http" => json!({"format":"traffic-policy/v3","http":{"headers":{
            "x-request-id":{"kind":"identity","formats":["uuid"]}
        }}}),
        "api" => json!({"id":"generated","match":{"api":"GET /api"},
            "effect":{"kind":"response_generated","fields":{
                "/id":{"contract":{"kind":"uuid_v4"},"proof":{
                    "source":"handler.py:12","fact":"Source generates a UUID for this response"}}
            }},"proof":{"source":"handler.py:12","fact":"Source generates a UUID for this response"}}),
        _ => unreachable!(),
    }
}

fn source(status: u16, valid: bool) -> serde_json::Value {
    let id = "11111111-1111-4111-8111-111111111111";
    let mut value =
        json!({"status":status,"headers":{"x-request-id":[id]},"body":body(json!({"id":id}))});
    if !valid {
        // Unknown scalar formats deliberately retain exact comparison. Use
        // invalid contract structure and an ambiguous header capture instead.
        value["body"] = body(json!({"id":{"unexpected":"object"}}));
        value["headers"]["X-Request-Id"] = json!([id]);
    }
    value
}

fn target(status: u16) -> serde_json::Value {
    json!({"version":1,"status":status,"body":body(json!({"error":"private-target-error"})),
        "request_sent_at":"2026-10-16T00:01:00Z"})
}

#[test]
fn response_status_differences_allow_plan_apply_without_claiming_target_validation() {
    for kind in ["json", "http", "api"] {
        for (source_status, target_status) in [(200, 500), (200, 201), (500, 200)] {
            let fixture = Fixture::new();
            fixture.replace_responses(source(source_status, true), target(target_status));
            write(&fixture.proposal, proposal(kind));
            fixture.confirm();
            let original_policy = fs::read(fixture.policy()).unwrap();
            let plan = fixture.plan().unwrap();
            let report = &plan.traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay", "{kind}");
            assert_eq!(report["verified"], false);
            assert_eq!(report["preflight"]["source_validations"], 1);
            assert_eq!(report["preflight"]["independent_target_validations"], 0);
            assert_eq!(report["preflight"]["missing_target_witnesses"], 0);
            assert_eq!(
                report["preflight"]["unvalidated_target_witnesses"],
                json!([{
                    "case_id":"00000000-0000-4000-8000-000000000001","surface":"api.response","reason":"response_status_differs",
                    "source_status":source_status,"target_status":target_status
                }])
            );
            assert!(!report.to_string().contains("private-target-error"));
            assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert_eq!(applied.traffic_e2e_report["verified"], false);
            assert_ne!(fs::read(fixture.policy()).unwrap(), original_policy);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
            let dir = fixture
                .state()
                .case_source
                .as_ref()
                .unwrap()
                .join("apis/api/00000000-0000-4000-8000-000000000001");
            let assertion = crate::assert_recorded_response(crate::ResponseAssertionOptions {
                case_id: "00000000-0000-4000-8000-000000000001".into(),
                request: dir.join("request.json"),
                expected_response: dir.join("expected-response.json"),
                actual_response: fixture
                    .paths
                    .replay
                    .parent()
                    .unwrap()
                    .join("00000000-0000-4000-8000-000000000001.json"),
                policy: fixture.policy(),
            })
            .unwrap();
            assert!(!assertion.passed);
            assert!(
                assertion
                    .differences
                    .iter()
                    .any(|diff| diff.pointer == "$status"
                        && diff.expected_status == Some(source_status)
                        && diff.actual_status == Some(target_status))
            );
        }
    }
}

#[test]
fn response_status_difference_does_not_waive_invalid_source_rules_or_target_artifacts() {
    for kind in ["json", "http", "api"] {
        let fixture = Fixture::new();
        fixture.replace_responses(source(200, false), target(500));
        write(&fixture.proposal, proposal(kind));
        fixture.confirm();
        assert!(
            fixture.plan().is_err(),
            "{kind}: invalid Source must reject"
        );
        assert!(fixture.state().rule_plan.is_none());
    }
    for scenario in ["version", "body", "tampered", "stale"] {
        let fixture = Fixture::new();
        let mut after = target(500);
        if scenario == "version" {
            after["version"] = json!(2);
        }
        if scenario == "body" {
            after["body"] = json!({"encoding":"base64","data":"!invalid!","truncated":false});
        }
        fixture.replace_responses(source(200, true), after);
        write(&fixture.proposal, proposal("json"));
        fixture.confirm();
        let actual = fixture
            .paths
            .replay
            .parent()
            .unwrap()
            .join("00000000-0000-4000-8000-000000000001.json");
        if scenario == "stale" {
            let plan = fixture.plan().unwrap();
            write(&actual, target(503));
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        } else {
            if scenario == "tampered" {
                write(&actual, target(503));
            }
            assert!(
                fixture.plan().is_err(),
                "{scenario}: invalid artifact must reject"
            );
        }
        assert!(
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
                .unwrap()
                .json
                .is_none()
        );
    }
}

#[test]
fn equal_error_response_status_still_validates_selected_fields_strictly() {
    for valid in [false, true] {
        let fixture = Fixture::new();
        let mut after = source(500, valid);
        after["version"] = json!(1);
        after["request_sent_at"] = json!("2026-10-16T00:01:00Z");
        fixture.replace_responses(source(500, true), after);
        write(&fixture.proposal, proposal("json"));
        fixture.confirm();
        let planned = fixture.plan();
        if valid {
            let report = planned.unwrap().traffic_e2e_report;
            assert_eq!(report["preflight"]["independent_target_validations"], 1);
            assert_eq!(
                report["preflight"]["unvalidated_target_witnesses"],
                json!([])
            );
        } else {
            let report = planned.unwrap().traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(report["preflight"]["independent_target_validations"], 0);
        }
    }
}

#[test]
fn response_status_failure_in_another_case_does_not_block_proven_identity_rule() {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |_, source| {
        let case = source.join("apis/api/00000000-0000-4000-8000-000000000002");
        fs::create_dir_all(&case).unwrap();
        write(
            &case.join("request.json"),
            json!({"timestamp":"2026-10-16T00:00:00Z",
            "method":"GET","uri":"/api","body":body(json!({}))}),
        );
        fs::write(case.join("dependencies.jsonl"), "").unwrap();
        vec![case]
    });
    let mut after = source(200, true);
    after["version"] = json!(1);
    after["body"] = body(json!({"id":"22222222-2222-4222-8222-222222222222"}));
    after["request_sent_at"] = json!("2026-10-16T00:01:00Z");
    fixture.replace_responses(source(200, true), after);
    fixture.replace_case_responses(
        "00000000-0000-4000-8000-000000000002",
        source(200, true),
        target(500),
    );
    write(&fixture.proposal, proposal("json"));
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let report = &plan.traffic_e2e_report;
    assert_eq!(report["status"], "planned_needs_replay");
    assert_eq!(report["preflight"]["source_validations"], 2);
    assert_eq!(report["preflight"]["independent_target_validations"], 1);
    assert_eq!(
        report["preflight"]["unvalidated_target_witnesses"][0]["case_id"],
        "00000000-0000-4000-8000-000000000002"
    );
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}
