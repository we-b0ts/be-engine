//! Automatic textual times need observations, without authored permissions.
use super::*;

fn fixture(target_at: &str) -> Fixture {
    let fixture = Fixture::new();
    fixture.replace_responses(
        json!({"status":200,"timestamp":"2026-10-16T00:00:30Z",
            "body":body(json!({"members":[1,2],"created":"2026-10-16T00:00:30Z"}))}),
        json!({"version":1,"status":200,"request_sent_at":"2026-10-16T00:01:00Z",
            "response_completed_at":"2026-10-16T00:02:30Z",
            "body":body(json!({"members":[2,1],"created":target_at}))}),
    );
    fixture.confirm();
    fixture
}

#[test]
fn automatic_response_time_preflight_uses_completion_without_an_authored_time_field() {
    for target in ["2026-10-16T00:02:30Z", "2026-10-16T00:04:03Z"] {
        let fixture = fixture(target);
        let planned = fixture.plan();
        if target == "2026-10-16T00:04:03Z" {
            assert!(
                format!("{:#}", planned.unwrap_err())
                    .contains("time difference does not preserve the anchor difference")
            );
            continue;
        }
        let planned = planned.unwrap();
        let report = &planned.traffic_e2e_report;
        assert!(report["json"]["fields"].get("/created").is_none());
        assert_eq!(report["source_proofs"]["rules"], json!([]));
        assert_eq!(report["preflight"]["independent_target_validations"], 1);
        assert!(
            report["rule_ids"]
                .as_array()
                .unwrap()
                .iter()
                .all(|id| id != "builtin.time")
        );
        apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}

#[test]
fn builtin_time_is_not_positive_source_proof_for_an_unobserved_authored_field() {
    let fixture = fixture("2026-10-16T00:02:30Z");
    fixture.replace_responses(
        json!({"status":200,"timestamp":"2026-10-16T00:00:30Z","body":body(json!({"created":"2026-10-16T00:00:30Z"}))}),
        json!({"version":1,"status":200,"request_sent_at":"2026-10-16T00:01:00Z",
            "response_completed_at":"2026-10-16T00:02:30Z","body":body(json!({"created":"2026-10-16T00:02:30Z"}))}),
    );
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/not_observed":{"kind":"unordered"}
        }}}),
    );
    let error = format!("{:#}", fixture.plan().unwrap_err());
    assert!(
        error.contains("global.json") && error.contains("selects no complete Source witness"),
        "{error}"
    );
}

#[test]
fn explicit_time_settings_apply_without_source_rule_proof_and_still_require_replay() {
    let fixture = fixture("2026-10-16T00:02:30Z");
    // This transaction changes only an engine interpretation setting. Keep the
    // strict remainder equal, since no unordered permission is being authored.
    fixture.replace_responses(
        json!({"status":200,"timestamp":"2026-10-16T00:00:30Z","body":body(json!({"created":"2026-10-16T00:00:30Z"}))}),
        json!({"version":1,"status":200,"request_sent_at":"2026-10-16T00:01:00Z",
            "response_completed_at":"2026-10-16T00:02:30Z","body":body(json!({"created":"2026-10-16T00:02:30Z"}))}),
    );
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy-change/v1","replace_sections":["time"],
        "policy":{"format":"traffic-policy/v3","time":{"default_utc_offset":"+05:30"}}}),
    );
    let planned = fixture.plan().unwrap();
    assert_eq!(planned.traffic_e2e_report["rule_ids"], json!([]));
    assert_eq!(
        planned.traffic_e2e_report["source_proofs"]["rules"],
        json!([])
    );
    assert_eq!(planned.traffic_e2e_report["requires_fresh_replay"], true);
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    let applied =
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
    assert_eq!(applied.time.default_utc_offset, "+05:30");
    assert!(applied.json.is_none() && applied.rules.is_empty());
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}
