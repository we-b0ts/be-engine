//! Global format sections use the same sealed transaction as contextual rules.
use super::*;

#[test]
fn global_json_formats_plan_and_apply_without_resource_api_or_binding_declarations() {
    let fixture = Fixture::new();
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v2", "json":{"fields":{"/members":{"kind":"unordered"}}}}),
    );
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    assert!(
        plan.traffic_e2e_report["rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "global.json")
    );
    assert!(
        plan.traffic_e2e_report["preflight"]["source_validations"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        plan.traffic_e2e_report["json"]["fields"]["/members"]["kind"],
        "unordered"
    );
    assert!(!plan.traffic_e2e_report.to_string().contains("\"binding\""));
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    let document =
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
    assert!(document.json.is_some());
    assert!(document.resources.is_empty());
    assert!(fixture.state().rule_replay_pending);
}

#[test]
fn global_format_plan_rejects_a_changed_source_payload_before_apply() {
    let fixture = Fixture::new();
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v2", "json":{"fields":{"/members":{"kind":"unordered"}}}}),
    );
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1/expected-response.json");
    fs::write(&case, b"changed after sealed global plan").unwrap();
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
    assert!(
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap()
            .json
            .is_none()
    );
}
