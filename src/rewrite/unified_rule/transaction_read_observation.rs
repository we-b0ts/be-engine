//! Absent observations require complete Source lifetimes and fresh Target certification.
use super::*;
use serde_json::Value;

fn event(sequence: usize, command: &str, response: &[u8]) -> Value {
    json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "connection_id":uuid::Uuid::nil(),"sequence":sequence,"target_host":"cache.test","target_port":6379,
        "database":0,"resp_version":2,"command":command,"args":[raw_body(b"cancel:1")],
        "response_kind":if command=="GET" {"null"}else{"integer"},
        "response":raw_body(response),"outcome":"response","replay_safe":true})
}

#[test]
fn absent_read_observation_plan_apply_freezes_boundaries_and_requires_fresh_replay() {
    for scenario in ["valid", "non_nil", "unbounded", "stale", "replace"] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
            if scenario == "replace" {
                write(
                    &root.join(".traffic-e2e/policy.yaml"),
                    json!({"format":"traffic-policy/v2",
                    "rules":[{"id":"finite-poll","match":{"api":"GET /api",
                        "resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
                        "operation":"GET","key":{"kind":"affix","prefix":"cancel:"}},
                        "effect":{"kind":"redis_read_commutation"}}]}),
                );
            }
            let mut events = vec![
                event(1, "DEL", b":0\r\n"),
                event(2, "GET", b"$-1\r\n"),
                event(3, "DEL", b":0\r\n"),
            ];
            if scenario == "non_nil" {
                events[1]["response"] = raw_body(b"$4\r\ntrue\r\n");
            }
            if scenario == "unbounded" {
                events.pop();
            }
            fs::write(
                source.join("apis/api/case-1/dependencies.jsonl"),
                events
                    .iter()
                    .map(|event| format!("{event}\n"))
                    .collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        let policy = json!({"format":"traffic-policy/v2", "redis":{"keys":{
            "cancel:*":{"read_observation":true,"proof":{"source":"session.py:10-40",
                "fact":"Independent cancellation polling reads nil between successful registration and cleanup deletions; the full Source lifetime is captured"}}
        }}});
        let proposal = if scenario == "replace" {
            json!({"format":"traffic-policy-change/v1","replace_rules":["finite-poll"],"policy":policy})
        } else {
            policy
        };
        write(&fixture.proposal, proposal);
        fixture.confirm();
        let dependencies = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1/dependencies.jsonl");
        let original = fs::read(&dependencies).unwrap();
        let plan = fixture.plan();
        if matches!(scenario, "non_nil" | "unbounded") {
            assert!(plan.is_err(), "{scenario}");
            continue;
        }
        let plan = plan.unwrap();
        if scenario == "replace" {
            assert_eq!(
                plan.traffic_e2e_report["replaced_rules"][0]["id"],
                "finite-poll"
            );
        }
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["stateful_target_obligations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
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
