//! A new delivery permission uses the ordinary protected plan/apply transaction.
use super::*;
use serde_json::Value;

fn proposal() -> Value {
    json!({"id":"current-block","match":{"api":"GET /api","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"SET","key":{"kind":"exact","value":"current:7"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
        "proof":{"source":"session.py:42","fact":"Source stores a generated block identity and reads that exact key before appending its content"}})
}

fn event(sequence: usize, command: &str, args: &[&str], response: &[u8]) -> Value {
    json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "connection_id":uuid::Uuid::nil(),"sequence":sequence,"target_host":"cache.test","target_port":6379,
        "database":0,"resp_version":2,"command":command,"args":args.iter().map(|v|raw_body(v.as_bytes())).collect::<Vec<_>>(),
        "response_kind":if command=="SET" {"simple_string"}else if command=="GET" {"bulk_string"}else{"integer"},
        "response":raw_body(response),"outcome":"response","replay_safe":true})
}

#[test]
fn read_back_public_plan_apply_requires_source_read_proof_and_fresh_target_replay() {
    for positive_read in [true, false] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
            crate::platform::encryption_key::load_or_create(root).unwrap();
            let mut prior = proposal();
            prior["effect"].as_object_mut().unwrap().remove("read_back");
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v2","rules":[prior]}),
            );
            let mut events = vec![event(1, "SET", &["current:7", "old"], b"+OK\r\n")];
            if positive_read {
                events.push(event(2, "GET", &["current:7"], b"$3\r\nold\r\n"));
            }
            events.push(event(3, "APPEND", &["content:old", "x"], b":1\r\n"));
            fs::write(
                source.join("apis/api/case-1/dependencies.jsonl"),
                events.iter().map(|e| format!("{e}\n")).collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        write(&fixture.proposal, proposal());
        fixture.confirm();
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1");
        let path = case.join("dependencies.jsonl");
        let original = fs::read(&path).unwrap();
        let planned = fixture.plan();
        if positive_read {
            let plan = planned.unwrap();
            assert_eq!(plan.traffic_e2e_report["verified"], false);
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
                json!(["current-block"])
            );
            let expanded = &plan.traffic_e2e_report["expanded_rules"][0];
            assert_eq!(
                expanded["effect"]["read_back"][0]["contract"]["operation"],
                "GET"
            );
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        } else {
            assert!(planned.is_err());
        }
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn finite_read_back_state_epoch_upgrade_uses_complete_source_and_normal_plan_apply_guards() {
    for scenario in [
        "valid",
        "stale",
        "wrong-value",
        "before-capture",
        "no-positive-read",
        "expiry-observer",
        "missing-proof",
    ] {
        let mut prior = proposal();
        prior["effect"]["read_back"][0]["proof"] = json!({
            "source":"session.py:50","fact":"The same-key GET reads the previously written current identity"});
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
            crate::platform::encryption_key::load_or_create(root).unwrap();
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v2","rules":[prior.clone()]}),
            );
            let mut events = vec![
                event(1, "GET", &["current:7"], b"$-1\r\n"),
                event(2, "SET", &["current:7", "old"], b"+OK\r\n"),
                event(3, "GET", &["current:7"], b"$3\r\nold\r\n"),
                event(4, "APPEND", &["content:old", "x"], b":1\r\n"),
                event(5, "GET", &["current:7"], b"$3\r\nold\r\n"),
                event(6, "DEL", &["current:7"], b":1\r\n"),
                event(7, "GET", &["current:7"], b"$-1\r\n"),
            ];
            if scenario == "wrong-value" {
                events[4]["response"] = raw_body(b"$-1\r\n");
            }
            if scenario == "before-capture" {
                events[0]["response"] = raw_body(b"$3\r\nold\r\n");
            }
            if scenario == "no-positive-read" {
                events.retain(|event| !matches!(event["sequence"].as_u64(), Some(3 | 5)));
            }
            if scenario == "expiry-observer" {
                events.push(event(8, "TTL", &["current:7"], b":-2\r\n"));
            }
            fs::write(
                source.join("apis/api/case-1/dependencies.jsonl"),
                events.iter().map(|e| format!("{e}\n")).collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        let mut upgrade = prior.clone();
        upgrade["effect"]["read_back"][0]["state_epochs"] = json!({
        "source":"session.py:51","fact":if scenario == "missing-proof" {""} else {
            "Scheduling changes repeated GET counts; SET and DEL exclusively define the same Case-owned identity state"
        }});
        write(&fixture.proposal, upgrade);
        fixture.confirm();
        let dependencies = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1/dependencies.jsonl");
        let original_dependencies = fs::read(&dependencies).unwrap();
        let original_policy = fs::read(fixture.policy()).unwrap();
        let planned = fixture.plan();
        if !matches!(scenario, "valid" | "stale") {
            assert!(planned.is_err(), "{scenario}");
            assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
            continue;
        }
        let plan = planned.unwrap();
        let expanded = &plan.traffic_e2e_report["expanded_rules"][0];
        assert_eq!(expanded["proof"], prior["proof"]);
        assert_eq!(
            expanded["effect"]["read_back"][0]["proof"],
            prior["effect"]["read_back"][0]["proof"]
        );
        assert_eq!(
            expanded["effect"]["read_back"][0]["contract"]["state_epochs"]["source"],
            "session.py:51"
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["current-block"])
        );
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        if scenario == "stale" {
            fs::write(
                &dependencies,
                format!("{}\n", std::str::from_utf8(&original_dependencies).unwrap()),
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
            assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
            assert_eq!(fs::read(&dependencies).unwrap(), original_dependencies);
        }
    }
}
