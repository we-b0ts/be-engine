//! Global SQL JSON formats preserve complete identities and the SQL remainder.
use super::*;

#[test]
fn mysql_global_json_composes_identity_time_and_unordered_fields_without_capture_rules() {
    for scenario in ["valid", "business", "identity", "time", "shape"] {
        let fixture = Fixture::new();
        write(
            &fixture.proposal,
            json!({"format":"traffic-policy/v2","json":{"fields":{
                "/members":{"kind":"unordered"},
                "/blocks/*/id":{"kind":"identity","formats":["uuid"]},
                "/blocks/*/timestamp":{"kind":"time","formats":["unix_seconds"]}
            }}}),
        );
        let source_id = "11111111-1111-4111-8111-111111111111";
        let target_id = "22222222-2222-4222-8222-222222222222";
        let payload = |id, time| json!({"blocks":[{"id":id,"timestamp":time,"stable":7},{"id":id,"timestamp":time+1,"stable":7}],"status":"done"});
        let source = payload(source_id, 1792108800_i64).to_string();
        let event = json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
            "connection_id":uuid::Uuid::nil(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","command":"COM_QUERY",
            "sql":format!("UPDATE results SET payload='{source}' WHERE id=7"),"response":{"status":"ok"},"outcome":"response"});
        dependency_transaction::install(&fixture, event, |raw| {
            let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let mut target = payload(target_id, 1792108860_i64);
            match scenario {
                "business" => target["status"] = json!("changed"),
                "identity" => {
                    target["blocks"][1]["id"] = json!("33333333-3333-4333-8333-333333333333")
                }
                "time" => target["blocks"][1]["timestamp"] = json!(1792108900_i64),
                "shape" => {
                    target["blocks"].as_array_mut().unwrap().pop();
                }
                _ => {}
            }
            envelope["sql"] = json!(format!("UPDATE results SET payload='{target}' WHERE id=7"));
            serde_json::to_vec(&envelope).unwrap()
        });
        fixture.confirm();
        let planned = fixture.plan();
        if scenario != "valid" {
            assert!(planned.is_err(), "{scenario}");
            continue;
        }
        let plan = planned.unwrap();
        assert!(
            plan.traffic_e2e_report["expanded_rules"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            2
        );
        apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}
