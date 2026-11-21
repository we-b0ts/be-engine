//! Finite read commutation requires complete Source traces and a new genuine Target Replay.
use super::*;
use serde_json::Value;

fn proposal() -> Value {
    json!({"id":"poll","match":{"api":"GET /api","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"GET","key":{"kind":"numeric","prefix":"cancel:"}},"effect":{"kind":"redis_read_commutation"},
        "proof":{"source":"session.py:42","fact":"Independent nil cancellation polling has no ordering relation to unrelated content writes; every read stays finite"}})
}

fn event(sequence: usize, command: &str, args: &[&str], response: &[u8]) -> Value {
    json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "connection_id":uuid::Uuid::nil(),"sequence":sequence,"target_host":"cache.test","target_port":6379,
        "database":0,"resp_version":2,"command":command,"args":args.iter().map(|v|raw_body(v.as_bytes())).collect::<Vec<_>>(),
        "response_kind":if command=="GET" {"bulk_string"}else{"integer"},
        "response":raw_body(response),"outcome":"response","replay_safe":true})
}

#[test]
fn read_commutation_public_plan_apply_validates_complete_source_and_preserves_stale_guards() {
    for scenario in ["valid", "changed", "absent", "stale"] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |_, source| {
            let mut events = vec![
                event(1, "GET", &["cancel:1"], b"$-1\r\n"),
                event(2, "APPEND", &["content:1", "cd"], b":4\r\n"),
                event(3, "GET", &["cancel:1"], b"$-1\r\n"),
            ];
            if scenario == "changed" {
                events[2]["response"] = raw_body(b"$4\r\ntrue\r\n");
            }
            if scenario == "absent" {
                events.clear();
            }
            fs::write(
                source.join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl"),
                events.iter().map(|e| format!("{e}\n")).collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        write(&fixture.proposal, proposal());
        fixture.confirm();
        let dependencies = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl");
        let original = fs::read(&dependencies).unwrap();
        let plan = fixture.plan();
        if matches!(scenario, "changed" | "absent") {
            assert!(plan.is_err(), "{scenario}");
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(plan.traffic_e2e_report["preflight"]["rules"]["poll"], 2);
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["poll"])
        );
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
