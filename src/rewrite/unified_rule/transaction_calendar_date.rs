//! Calendar permissions use the same protected evidence and plan/apply gates.
use super::*;

#[test]
fn calendar_date_plan_apply_preserves_strict_counters_and_requires_fresh_replay() {
    for response in [false, true] {
        for change in ["valid", "counter", "date"] {
            let fixture = Fixture::new();
            write(
                &fixture.proposal,
                json!({"format":"traffic-policy/v2","json":{"fields":{
                    "/members":{"kind":"unordered"},
                    "/lastActiveDate":{"kind":"time","formats":[{"format":"calendar_date","utc_offset":"+08:00"}]}
                }}}),
            );
            let body = json!({"lastActiveDate":"2026-10-16","experience":7}).to_string();
            let event = json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
                "connection_id":uuid::Uuid::nil(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","username":"writer","command":"COM_QUERY",
                "sql":if response {"SELECT payload FROM pets WHERE id=7".into()} else {format!("UPDATE pets SET payload='{body}' WHERE id=7")},
                "response":if response {json!({"status":"resultset","columns":[{"name":"payload","column":"payload","family":"string","sql_type":"VARCHAR"}],"rows":[[{"kind":"string","value":body}]]})} else {json!({"status":"ok"})},
                "parse_warnings":[],"outcome":"response"});
            super::dependency_transaction::install(&fixture, event, |raw| {
                let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                if response {
                    envelope["request"]["request_started_at"] = json!("2026-10-16T00:01:00Z");
                    envelope["response_delivered_at"] = json!("2026-10-16T00:01:00Z");
                }
                if change == "valid" {
                    return serde_json::to_vec(&envelope).unwrap();
                }
                let mut changed = json!({"lastActiveDate":"2026-10-16","experience":7});
                if change == "counter" {
                    changed["experience"] = json!(8);
                }
                if change == "date" {
                    changed["lastActiveDate"] = json!("2026-10-17");
                }
                if response {
                    envelope["response"]["rows"][0][0]["value"] = json!(changed.to_string());
                } else {
                    envelope["sql"] =
                        json!(format!("UPDATE pets SET payload='{}' WHERE id=7", changed));
                }
                serde_json::to_vec(&envelope).unwrap()
            });
            fixture.confirm();
            let planned = fixture.plan();
            if change != "valid" && !(response && change == "date") {
                assert!(planned.is_err(), "response={response}, change={change}");
                continue;
            }
            let plan = planned.unwrap();
            let preflight = &plan.traffic_e2e_report["preflight"];
            assert_eq!(
                preflight["independent_target_validations"],
                if response { 1 } else { 2 }
            );
            assert_eq!(preflight["derived_delivery_validations"], 0);
            assert_eq!(plan.traffic_e2e_report["verified"], false);
            let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        }
    }
}
