//! Public refresh plans freeze complete Source proof and require genuine Replay.
use super::*;

fn fixture() -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
        write(
            &root.join(".traffic-e2e/policy.yaml"),
            json!({"format":"traffic-policy/v2","json":{"fields":{
                "/last_activity_at":{"kind":"time","formats":["rfc3339"]}
            }}}),
        );
        let first = json!({"task":7,"last_activity_at":"2026-10-16T00:00:00Z"})
            .to_string()
            .into_bytes();
        let next = json!({"task":7,"last_activity_at":"2026-10-16T00:00:02Z"})
            .to_string()
            .into_bytes();
        let mut bulk = format!("${}\r\n", first.len()).into_bytes();
        bulk.extend(&first);
        bulk.extend(b"\r\n");
        let rows = [
            (
                "SET",
                vec![b"activity:1".as_slice(), &first, b"EX", b"3600"],
                b"+OK\r\n".as_slice(),
            ),
            ("GET", vec![b"activity:1".as_slice()], bulk.as_slice()),
            (
                "SET",
                vec![b"activity:1".as_slice(), &next, b"EX", b"3600"],
                b"+OK\r\n".as_slice(),
            ),
            ("DEL", vec![b"activity:1".as_slice()], b":1\r\n".as_slice()),
        ];
        let events=rows.into_iter().enumerate().map(|(index,(command,args,response))|json!({
            "event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":index+1,
            "timestamp":format!("2026-10-16T00:00:0{index}Z"),"duration_ms":0,"outcome":"response",
            "target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,"command":command,
            "args":args.into_iter().map(raw_body).collect::<Vec<_>>(),"response":raw_body(response),
            "response_kind":"bulk_string","replay_safe":true})).collect::<Vec<_>>();
        fs::write(
            source.join("apis/api/case-1/dependencies.jsonl"),
            events.iter().map(|e| format!("{e}\n")).collect::<String>(),
        )
        .unwrap();
        vec![]
    });
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v2","redis":{"keys":{
            "activity:*":{"activity_refresh":{"fields":["/last_activity_at"]},
                "proof":{"source":"session.py:touch","fact":"Source reads current metadata, refreshes only its timestamp and preserves fixed TTL inside an owned lifetime"}}
        }}}),
    );
    fixture.confirm();
    fixture
}

#[test]
fn activity_refresh_public_plan_apply_requires_source_proof_and_fresh_replay() {
    for stale in [false, true] {
        let fixture = fixture();
        let before = fs::read(fixture.policy()).unwrap();
        let plan = fixture.plan().unwrap();
        assert_eq!(plan.traffic_e2e_report["status"], "planned_needs_replay");
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        assert!(
            plan.traffic_e2e_report["preflight"]["source_validations"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        assert_eq!(
            plan.traffic_e2e_report["expanded_rules"][0]["effect"]["kind"],
            "redis_activity_refresh"
        );
        assert_eq!(fs::read(fixture.policy()).unwrap(), before);
        if stale {
            let trace = fixture
                .state()
                .case_source
                .as_ref()
                .unwrap()
                .join("apis/api/case-1/dependencies.jsonl");
            fs::write(trace, b"changed synthetic Source after plan").unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
            assert_eq!(fs::read(fixture.policy()).unwrap(), before);
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
            let policy = fs::read_to_string(fixture.policy()).unwrap();
            assert!(policy.contains("activity_refresh"));
            assert!(!policy.contains("session.py:touch"));
            let compiled = crate::policy::parse_policy(&policy)
                .and_then(|p| crate::policy::compile_policy(&p))
                .unwrap();
            assert_eq!(compiled.native.len(), 1);
        }
    }
}
