//! Calendar permissions use the same protected evidence and plan/apply gates.
use super::*;

#[test]
fn finalized_partial_calendar_plan_still_checks_independent_targets_and_stale_artifacts() {
    for scenario in [
        "valid",
        "counter",
        "unfinalized",
        "stale-source",
        "stale-target",
    ] {
        let fixture = Fixture::new();
        fixture.replace_response_bodies(b"{}", b"{}");
        write(
            &fixture.proposal,
            json!({"format":"traffic-policy/v3","json":{"fields":{
                "/lastActiveDate":{"kind":"time","formats":[{"format":"calendar_date","utc_offset":"+08:00"}]}
            }}}),
        );
        let payload = json!({"lastActiveDate":"2026-10-16","currentStreak":86}).to_string();
        let event = json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
            "connection_id":uuid::Uuid::nil(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app",
            "command":"COM_QUERY","sql":format!("UPDATE pets SET payload='{payload}' WHERE id=7"),
            "response":{"status":"ok"},"outcome":"response"});
        dependency_transaction::install(&fixture, event, |raw| {
            if scenario != "counter" {
                return raw;
            }
            let mut target: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            target["sql"] = target["sql"].as_str().unwrap().replace("86", "87").into();
            serde_json::to_vec(&target).unwrap()
        });
        for path in [&fixture.paths.replay, &fixture.paths.aggregate] {
            let mut report: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            report["complete"] = false.into();
            if path == &fixture.paths.replay {
                report["finalized"] = (scenario != "unfinalized").into();
            }
            write(path, report);
        }
        fixture.confirm();
        let planned = fixture.plan();
        if scenario == "unfinalized" {
            assert!(planned.is_err());
            assert!(fixture.state().rule_plan.is_none());
            continue;
        }
        let plan = planned.unwrap();
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        let preflight = &plan.traffic_e2e_report["preflight"];
        assert_eq!(
            preflight["independent_target_validations"],
            u64::from(scenario != "counter")
        );
        if scenario == "counter" {
            assert_eq!(
                preflight["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        }
        if scenario == "stale-source" {
            let source = fixture
                .state()
                .case_source
                .as_ref()
                .unwrap()
                .join("apis/api/00000000-0000-4000-8000-000000000001/dependencies.jsonl");
            fs::write(source, "\n").unwrap();
        } else if scenario == "stale-target" {
            let mut replay: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
            replay["changed_after_plan"] = true.into();
            write(&fixture.paths.replay, replay);
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id);
        if scenario.starts_with("stale-") {
            assert!(applied.is_err(), "{scenario}");
            continue;
        }
        assert_eq!(
            applied.unwrap().traffic_e2e_report["requires_fresh_replay"],
            true
        );
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}
