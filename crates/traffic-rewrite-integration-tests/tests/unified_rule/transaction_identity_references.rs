//! Existing captures gain references only with complete Source use and fresh Replay.
use super::*;

fn proposal(extended: bool) -> serde_json::Value {
    let mut rule = json!({"id":"block","match":{"api":"GET /api","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":"SET","key":{"kind":"exact","value":"current:7"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}]},
        "proof":{"source":"session.py:create","fact":"Source stores a generated block identity"}});
    if extended {
        rule["effect"]["references"].as_array_mut().unwrap().push(json!({
            "contract":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"}},
            "proof":{"source":"completion.py:result","fact":"The completed SQL JSON result contains the same previously captured block identity"}}));
    }
    rule
}

#[test]
fn identity_reference_extension_public_plan_apply_proves_use_after_capture_and_freezes_evidence() {
    for scenario in ["valid", "absent", "before-capture", "stale"] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
            crate::test_support::load_or_create_encryption_key(root).unwrap();
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v3","rules":[proposal(false)]}),
            );
            let redis = |sequence, command, args: &[&str], response: &str| {
                json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
                "connection_id":uuid::Uuid::nil(),"sequence":sequence,"target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,
                "command":command,"args":args.iter().map(|v| raw_body(v.as_bytes())).collect::<Vec<_>>(),
                "response_kind":if command=="SET" {"simple_string"} else {"integer"},"response":raw_body(response.as_bytes()),"outcome":"response","replay_safe":true})
            };
            let mut events = vec![
                redis(1, "SET", &["current:7", "old"], "+OK\r\n"),
                redis(2, "APPEND", &["content:old", "x"], ":1\r\n"),
            ];
            if scenario != "absent" {
                let event = json!({"event_type":"mysql_exchange","timestamp":if scenario=="before-capture" {"2026-10-15T23:59:59Z"} else {"2026-10-16T00:00:01Z"},"duration_ms":0,
                    "connection_id":"11111111-1111-4111-8111-111111111111","query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","username":"writer",
                    "command":"COM_QUERY","sql":"UPDATE results SET payload='{\"blocks\":[{\"id\":\"old\",\"stable\":7}]}' WHERE id=1","response":{"status":"ok"},"parse_warnings":[],"outcome":"response"});
                events.push(event);
            }
            fs::write(
                source.join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl"),
                events.iter().map(|v| format!("{v}\n")).collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        write(&fixture.proposal, proposal(true));
        fixture.confirm();
        let path = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl");
        let original = fs::read(&path).unwrap();
        let plan = fixture.plan();
        if matches!(scenario, "absent" | "before-capture") {
            assert!(plan.is_err(), "{scenario}");
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(
            plan.traffic_e2e_report["expanded_rules"][0]["effect"]["references"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        if scenario == "stale" {
            fs::write(
                fixture
                    .state()
                    .case_source
                    .as_ref()
                    .unwrap()
                    .join("dependencies.jsonl"),
                "tampered authoritative Source occurrence",
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        } else {
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }
}
