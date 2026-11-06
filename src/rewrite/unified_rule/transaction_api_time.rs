//! API business times use protected independent response completion observations.
use super::*;

const SOURCE_START: i64 = 1_792_108_800;

fn proposal(_compact: bool) -> serde_json::Value {
    json!({"format":"traffic-policy/v3","json":{"fields":{
        "/expires_at":{"kind":"time","formats":["unix_seconds"]},
        "/created_at":{"kind":"time","formats":["unix_seconds"]}
    }}})
}

fn response(offset: i64) -> serde_json::Value {
    json!({"expires_at":SOURCE_START+3600+offset,"created_at":SOURCE_START+offset,
        "remaining":3600,"business":"exact"})
}

fn fixture() -> Fixture {
    fixture_with_clock(Some("2026-10-16T00:00:00Z"))
}

fn fixture_with_clock(timestamp: Option<&str>) -> Fixture {
    let fixture = Fixture::with_request_time(timestamp);
    fixture.replace_response_bodies(
        &serde_json::to_vec(&response(0)).unwrap(),
        &serde_json::to_vec(&response(60)).unwrap(),
    );
    write(&fixture.proposal, proposal(true));
    fixture.confirm();
    fixture
}

#[test]
fn api_time_source_validation_without_target_preserves_replay_obligation() {
    let fixture = fixture();
    let mut assertions: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.assertions).unwrap()).unwrap();
    assertions["cases"][0]["response"] = serde_json::Value::Null;
    write(&fixture.paths.assertions, assertions);
    let planned = fixture.plan().unwrap();
    let report = &planned.traffic_e2e_report;
    assert_eq!(report["status"], "planned_needs_replay");
    assert_eq!(report["preflight"]["source_validations"], 1);
    assert_eq!(report["preflight"]["independent_target_validations"], 0);
    assert_eq!(report["preflight"]["missing_target_witnesses"], 1);
    assert_eq!(report["verified"], false);
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}

#[test]
fn api_time_plan_apply_validates_source_and_independent_target_response_clocks() {
    for compact in [false, true] {
        let fixture = fixture();
        write(&fixture.proposal, proposal(compact));
        let planned = fixture.plan().unwrap();
        let report = &planned.traffic_e2e_report;
        assert_eq!(report["status"], "preflight_validated_requires_replay");
        assert_eq!(report["preflight"]["source_validations"], 1);
        assert_eq!(report["preflight"]["independent_target_validations"], 1);
        assert_eq!(report["preflight"]["missing_target_witnesses"], 0);
        assert_eq!(report["preflight"]["rules"]["global.json"], 1);
        assert_eq!(report["verified"], false);
        let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert_eq!(
            applied.traffic_e2e_report["status"],
            "applied_pending_replay"
        );
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}

#[test]
fn api_time_preflight_rejects_invalid_times_and_defers_existing_value_differences() {
    for (pointer, value) in [
        ("/expires_at", json!(SOURCE_START + 3600 + 70)),
        ("/created_at", json!(SOURCE_START + 70)),
        ("/remaining", json!(3670)),
        ("/business", json!("changed")),
    ] {
        let fixture = fixture();
        let mut target = response(60);
        *target.pointer_mut(pointer).unwrap() = value;
        fixture.replace_response_bodies(
            &serde_json::to_vec(&response(0)).unwrap(),
            &serde_json::to_vec(&target).unwrap(),
        );
        let plan = fixture.plan();
        if matches!(pointer, "/created_at" | "/expires_at") {
            let error = format!("{:#}", plan.unwrap_err());
            assert!(
                error.contains(pointer)
                    && error.contains("time difference does not preserve the anchor difference"),
                "{error}"
            );
            assert!(fixture.state().rule_plan.is_none());
        } else {
            let report = plan.unwrap().traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(
                report["preflight"]["preexisting_primary_differences"]["00000000-0000-4000-8000-000000000001"],
                1,
                "{pointer}"
            );
            assert_eq!(report["preflight"]["independent_target_validations"], 0);
        }
    }
}

#[test]
fn api_time_preflight_requires_each_response_clock_without_request_fallback() {
    for missing_source in [false, true] {
        let fixture = fixture();
        fixture.replace_responses(
            json!({"status":200,"body":body(response(0)),
                "timestamp":(!missing_source).then_some("2026-10-16T00:00:00Z")}),
            json!({"version":1,"status":200,"body":body(response(60)),
                "request_sent_at":"2026-10-16T00:01:00Z",
                "response_completed_at":missing_source.then_some("2026-10-16T00:01:00Z")}),
        );
        let error = format!("{:#}", fixture.plan().unwrap_err());
        assert!(
            error.contains("time relation requires independent source and target anchors"),
            "{error}"
        );
        assert!(fixture.state().rule_plan.is_none());
    }
}

#[test]
fn api_time_preflight_bounds_unequal_response_latency_without_a_generation_anchor() {
    for target_offset in [150, 243] {
        let fixture = fixture();
        fixture.replace_responses(
            json!({"status":200,"body":body(response(30)),"timestamp":"2026-10-16T00:00:30Z"}),
            json!({"version":1,"status":200,"body":body(response(target_offset)),
                "request_sent_at":"2026-10-16T00:01:00Z",
                "response_completed_at":"2026-10-16T00:02:30Z"}),
        );
        let planned = fixture.plan();
        if target_offset == 150 {
            assert_eq!(
                planned.unwrap().traffic_e2e_report["preflight"]["independent_target_validations"],
                1
            );
        } else {
            let error = format!("{:#}", planned.unwrap_err());
            assert!(
                error.contains("time difference does not preserve the anchor difference"),
                "{error}"
            );
        }
    }
}

#[test]
fn api_business_time_preflight_does_not_require_an_unrelated_request_clock() {
    let fixture = fixture_with_clock(None);
    assert_eq!(
        fixture.plan().unwrap().traffic_e2e_report["preflight"]["independent_target_validations"],
        1
    );
}
