//! Source-only SDK permissions retain the unified transaction and Replay obligation.
use super::*;

#[test]
fn client_metadata_public_plan_apply_requires_each_source_header_and_rejects_stale_evidence() {
    for scenario in ["valid", "missing", "stale"] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |_, source| {
            let headers = if scenario == "missing" {
                json!({"x-stainless-lang":["python"]})
            } else {
                json!({"x-stainless-lang":["python"],"x-stainless-runtime":["CPython"]})
            };
            let event = json!({"event_type":"http_exchange","id":"source-http","scheme":"http","authority":"client.test:8080","method":"POST","uri":"/responses",
                "request_body":body(json!({"input":"hello"})),"request_headers":headers,
                "response_status":200,"response_headers":{},"response_body":body(json!({"ok":true})),"timestamp":"2026-10-16T00:00:01Z","request_started_at":"2026-10-16T00:00:00Z","duration_ms":1000,"outcome":"response","error":null});
            fs::write(
                source.join("apis/api/case-1/dependencies.jsonl"),
                format!("{event}\n"),
            )
            .unwrap();
            vec![]
        });
        write(
            &fixture.proposal,
            json!({"id":"sdk","match":{"api":"GET /api","resource":{"protocol":"http","endpoint":"client.test:8080"},"operation":"POST","path":"/responses"},
            "effect":{"kind":"http_client_metadata","headers":["x-stainless-lang","x-stainless-runtime"]},
            "proof":{"source":"sdk.py:headers; consumer.py:route","fact":"Selected consumer and middleware do not use SDK runtime metadata"}}),
        );
        fixture.confirm();
        let dependencies = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1/dependencies.jsonl");
        let original = fs::read(&dependencies).unwrap();
        let plan = fixture.plan();
        if scenario == "missing" {
            assert!(plan.is_err());
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(plan.traffic_e2e_report["preflight"]["rules"]["sdk"], 1);
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        if scenario == "stale" {
            fs::write(
                &dependencies,
                format!("{}\n", std::str::from_utf8(&original).unwrap()),
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert_eq!(fs::read(&dependencies).unwrap(), original);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        }
    }
}
