//! Identity normalization and selected JSON times retain one strict SQL remainder.
use super::*;
use crate::verification_progress::fingerprint;

fn identity() -> serde_json::Value {
    json!({"id":"block","match":{"api":"GET /api","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"SET","key":{"kind":"exact","value":"current"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}},
                {"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"}}]},
        "proof":{"source":"session.py:write","fact":"Source captures a block id and later copies it into SQL JSON"}})
}

fn times() -> serde_json::Value {
    json!({"id":"block-times","surface":"dependency.request","match":{"api":"GET /api","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY","sql":"UPDATE results SET payload=? WHERE id=?"},
        "slot":{"sql_value":0},"codec":"json","contract":{"/blocks/*/timestamp":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}},
        "proof":{"source":"session.py:clock","fact":"Each block contains its own creation clock, reused in the SQL result"}})
}

#[test]
fn mysql_composite_plan_uses_scoped_accepted_bindings_and_keeps_unselected_fields_strict() {
    for native_times in [false, true] {
        for scenario in [
            "valid",
            "business",
            "shape",
            "wrong-method",
            "wrong-resource",
            "missing-audit",
            "other-case",
            "wrong-audit",
            "before-capture",
        ] {
            let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
                let mut rule = identity();
                if scenario == "wrong-method" {
                    rule["match"]["api"] = json!("POST /api");
                }
                if scenario == "wrong-resource" {
                    rule["effect"]["references"][1]["resource"]["username"] = json!("other");
                }
                write(
                    &root.join(".traffic-e2e/policy.yaml"),
                    json!({"format":"traffic-policy/v1","rules":[rule]}),
                );
                vec![]
            });
            write(&fixture.proposal, times());
            let time = chrono::DateTime::parse_from_rfc3339("2026-10-16T00:00:00Z")
                .unwrap()
                .timestamp();
            let payload = |id, t| json!({"blocks":[{"id":id,"timestamp":t,"stable":7},{"id":id,"timestamp":t+1,"stable":7}],"status":"done"});
            let source = payload("old", time).to_string();
            let event = json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
            "connection_id":uuid::Uuid::nil(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","username":"writer","command":"COM_QUERY",
            "sql":format!("UPDATE results SET payload='{source}' WHERE id=7"),"response":{"status":"ok"},"parse_warnings":[],"outcome":"response"});
            super::dependency_transaction::install(&fixture, event, |raw| {
                let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let mut body = payload("new", time + 60);
                if scenario == "business" {
                    body["status"] = json!("changed");
                }
                if scenario == "shape" {
                    body["blocks"].as_array_mut().unwrap().pop();
                }
                envelope["command"] = json!("COM_STMT_EXECUTE");
                envelope["sql"] = json!("UPDATE results SET payload=? WHERE id=?");
                envelope["params"] = json!([{"kind":"string","value":body.to_string()},{"kind":"integer","value":7}]);
                serde_json::to_vec(&envelope).unwrap()
            });
            let case = fixture
                .state()
                .case_source
                .as_ref()
                .unwrap()
                .join("apis/api/case-1");
            let dependencies = case.join("dependencies.jsonl");
            let capture = json!({"event_type":"redis_exchange","timestamp":if scenario=="before-capture" {"2026-10-16T00:00:01Z"} else {"2026-10-15T23:59:59Z"},"duration_ms":0,"connection_id":"11111111-1111-4111-8111-111111111111","sequence":1,
            "target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,"command":"SET","args":[raw_body(b"current"),raw_body(b"old")],"response_kind":"simple_string","response":raw_body(b"+OK\r\n"),"outcome":"response","replay_safe":true});
            let original = fs::read_to_string(&dependencies).unwrap();
            fs::write(&dependencies, format!("{capture}\n{original}")).unwrap();
            let original = fs::read(&dependencies).unwrap();
            let mut report: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
            report["replay_policy"]["dynamic_bindings"] = if scenario == "missing-audit" {
                json!([])
            } else {
                json!([{"case_id":if scenario=="other-case" {"another"} else {"case-1"},"rule_id":"block",
                "source_fingerprint":fingerprint(b"old"),"target_fingerprint":fingerprint(if scenario=="wrong-audit" {b"bad"} else {b"new"})}])
            };
            write(&fixture.paths.replay, report);
            if native_times {
                let mut proposal = times();
                proposal.as_object_mut().unwrap().remove("surface");
                proposal.as_object_mut().unwrap().remove("slot");
                proposal.as_object_mut().unwrap().remove("codec");
                proposal.as_object_mut().unwrap().remove("contract");
                proposal["effect"] = json!({"kind":"mysql_values","values":{"0":{"kind":"json","fields":{"/blocks/*/timestamp":{"relative_time":"unix_seconds"}}}}});
                write(&fixture.proposal, proposal);
            }
            fixture.confirm();
            let plan = fixture.plan();
            if scenario != "valid" {
                assert!(plan.is_err(), "{scenario}");
                continue;
            }
            let plan = plan.unwrap();
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                1
            );
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
                json!(["block"])
            );
            assert_eq!(plan.traffic_e2e_report["verified"], false);
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert_eq!(fs::read(dependencies).unwrap(), original);
        }
    }
}
