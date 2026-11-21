//! Additive proposals preserve context; whole-section replacement is explicit.
use super::*;

#[test]
fn public_plan_distinguishes_default_additions_and_explicit_section_replacements() {
    for replace_existing in [false, true] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v3",
                "json":{"fields":{"/existing":{"kind":"identity","formats":["uuid"]}}},
                "http":{"headers":{"x-existing":{"kind":"identity","formats":["uuid"]}}}}),
            );
            vec![]
        });
        let fields = json!({"/members":{"kind":"unordered"}});
        let policy = json!({"format":"traffic-policy/v3","json":{"fields":fields}});
        write(
            &fixture.proposal,
            if replace_existing {
                json!({"format":"traffic-policy-change/v1","replace_sections":["json"],"policy":policy})
            } else {
                policy
            },
        );
        fixture.confirm();
        let planned = fixture.plan().unwrap();
        let changes = &planned.traffic_e2e_report["declaration_changes"];
        assert_eq!(
            changes["json"]["mode"],
            if replace_existing { "replace" } else { "add" }
        );
        assert_eq!(changes["json"]["location"], "json.fields");
        assert_eq!(changes["json"]["added_fields"], json!(["/members"]));
        assert_eq!(changes["json"]["changed_fields"], json!([]));
        assert_eq!(
            changes["json"]["removed_fields"],
            if replace_existing {
                json!(["/existing"])
            } else {
                json!([])
            }
        );
        assert!(
            changes.get("http").is_none(),
            "unprovided sections retain their previous map"
        );
        assert_eq!(planned.traffic_e2e_report["requires_fresh_replay"], true);
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["declaration_changes"], *changes);
        assert_eq!(
            applied.traffic_e2e_report["status"],
            "applied_pending_replay"
        );
        let policy =
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
        assert!(policy.http.unwrap().headers.contains_key("x-existing"));
        assert_eq!(
            policy.json.unwrap().fields.contains_key("/existing"),
            !replace_existing
        );
    }
}

fn identity_fixture(formats: serde_json::Value) -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
        write(
            &root.join(".traffic-e2e/policy.yaml"),
            json!({"format":"traffic-policy/v3",
            "json":{"fields":{"/id":{"kind":"identity","formats":formats},"/kept":{"kind":"unordered"}}}}),
        );
        vec![]
    });
    fixture.replace_response_bodies(br#"{"id":"1"}"#, br#"{"id":"2"}"#);
    fixture
}

#[test]
fn public_format_addition_preserves_order_deduplicates_and_reports_only_added_formats() {
    let fixture = identity_fixture(json!(["uuid"]));
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/id":{"kind":"identity","formats":["decimal","uuid","decimal"]}
        }}}),
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["json"]["fields"]["/id"]["formats"],
        json!(["uuid", "decimal"])
    );
    let changes = &planned.traffic_e2e_report["declaration_changes"]["json"];
    assert_eq!(changes["mode"], "add");
    assert_eq!(changes["changed_fields"], json!(["/id"]));
    assert_eq!(changes["removed_fields"], json!([]));
    assert_eq!(changes["added_formats"]["/id"], json!(["decimal"]));
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    let policy =
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
    assert!(policy.json.as_ref().unwrap().fields.contains_key("/kept"));
    assert_eq!(
        serde_json::to_value(&policy.json.unwrap().fields["/id"]).unwrap()["formats"],
        json!(["uuid", "decimal"])
    );
}

#[test]
fn duplicate_addition_and_empty_maps_are_noops_and_clear_requires_explicit_replacement() {
    for proposed in [
        json!({}),
        json!({"/id":{"kind":"identity","formats":["decimal","uuid","decimal"]}}),
    ] {
        let fixture = identity_fixture(json!(["uuid", "decimal"]));
        write(
            &fixture.proposal,
            json!({"format":"traffic-policy/v3","json":{"fields":proposed}}),
        );
        fixture.confirm();
        let original = fs::read(fixture.policy()).unwrap();
        let planned = fixture.plan().unwrap();
        assert_eq!(planned.traffic_e2e_report["status"], "planned_no_change");
        assert_eq!(planned.traffic_e2e_report["declaration_changes"], json!({}));
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["status"], "applied_no_change");
        assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], false);
        assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    }
    let fixture = identity_fixture(json!(["uuid", "decimal"]));
    fixture.replace_response_bodies(br#"{"stable":true}"#, br#"{"stable":true}"#);
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy-change/v1","replace_sections":["json"],
        "policy":{"format":"traffic-policy/v3","json":{"fields":{}}}}),
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["declaration_changes"]["json"]["mode"],
        "replace"
    );
    assert_eq!(
        planned.traffic_e2e_report["declaration_changes"]["json"]["removed_fields"],
        json!(["/id", "/kept"])
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
    assert!(
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap()
            .json
            .unwrap()
            .fields
            .is_empty()
    );
}

#[test]
fn public_addition_cannot_change_an_existing_field_kind() {
    let fixture = identity_fixture(json!(["uuid"]));
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/id":{"kind":"time","formats":["unix_seconds"]}
        }}}),
    );
    fixture.confirm();
    let original = fs::read(fixture.policy()).unwrap();
    assert!(fixture.plan().is_err());
    assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    assert!(fixture.state().rule_plan.is_none());
}
