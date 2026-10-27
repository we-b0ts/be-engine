use super::*;

fn completed() -> serde_json::Value {
    json!({"format":"traffic-policy/v2","json":{"fields":{
        "/members":{"kind":"unordered"},
        "/status/completedAt":{"kind":"time","formats":[{"format":"iso8601_naive","utc_offset":"+00:00"}]}
    }}})
}

fn event(table: &str, status: &str, completed: serde_json::Value) -> serde_json::Value {
    let payload =
        json!({"status":{"status":status,"completedAt":completed},"progress":7}).to_string();
    json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "connection_id":uuid::Uuid::nil(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","username":"writer","command":"COM_QUERY",
        "sql":format!("UPDATE {table} SET payload='{payload}', updated_at='2026-10-16 00:00:00' WHERE {table}.id=7"),"response":{"status":"ok"},"outcome":"response","parse_warnings":[]})
}

#[test]
fn global_sql_json_formats_keep_null_exact_and_prepared_statements_strict() {
    for table in ["tasks_0001", "tasks_0002"] {
        for scenario in [
            "running",
            "completed",
            "running-nonnull",
            "progress",
            "bad-clock",
            "wrong-shard",
            "wrong-qualifier",
        ] {
            let fixture = Fixture::new();
            write(&fixture.proposal, completed());
            let running = scenario.starts_with("running");
            let status = if running { "RUNNING" } else { "COMPLETED" };
            let source_date = if running {
                serde_json::Value::Null
            } else {
                json!("2026-10-16T00:00:00")
            };
            super::dependency_transaction::install(
                &fixture,
                event(table, status, source_date),
                |raw| {
                    let mut target: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                    let date = if scenario == "running" {
                        serde_json::Value::Null
                    } else if scenario == "bad-clock" {
                        json!("2026-10-16T01:00:00")
                    } else {
                        json!("2026-10-16T00:01:00")
                    };
                    let payload=json!({"status":{"status":status,"completedAt":date},"progress":if scenario=="progress" {8} else {7}}).to_string();
                    let actual_table = if scenario == "wrong-shard" {
                        if table == "tasks_0001" {
                            "tasks_0002"
                        } else {
                            "tasks_0001"
                        }
                    } else {
                        table
                    };
                    let qualifier = if scenario == "wrong-qualifier" {
                        "tasks_0003"
                    } else {
                        actual_table
                    };
                    target["command"] = json!("COM_STMT_EXECUTE");
                    target["sql"] = json!(format!(
                        "UPDATE {actual_table} SET payload=?, updated_at=? WHERE {qualifier}.id=?"
                    ));
                    target["params"] = json!([{"kind":"string","value":payload},{"kind":"string","value":"2026-10-16 00:00:00"},{"kind":"integer","value":7}]);
                    serde_json::to_vec(&target).unwrap()
                },
            );
            let path = fixture
                .state()
                .case_source
                .as_ref()
                .unwrap()
                .join("apis/api/case-1/dependencies.jsonl");
            let original = fs::read(&path).unwrap();
            fixture.confirm();
            let planned = fixture.plan();
            if matches!(scenario, "running" | "completed") {
                let plan = planned.unwrap_or_else(|error| panic!("{table}/{scenario}: {error:#}"));
                assert_eq!(
                    plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                    2
                );
                assert_eq!(plan.traffic_e2e_report["verified"], false);
                assert_eq!(
                    apply_rewrite_rule(fixture.context(), &plan.plan_id)
                        .unwrap()
                        .traffic_e2e_report["requires_fresh_replay"],
                    true
                );
            } else if matches!(scenario, "wrong-shard" | "wrong-qualifier") {
                // A structurally unrelated search edge is excluded, never counted
                // as an independent successful validation of this Source row.
                if let Ok(plan) = planned {
                    assert_eq!(
                        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                        1
                    );
                    assert_eq!(plan.traffic_e2e_report["verified"], false);
                }
            } else {
                assert!(planned.is_err(), "{table}/{scenario}");
            }
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
}

#[test]
fn sql_value_table_discovery_retains_source_entry_for_unrelated_target_statement() {
    for related in [false, true] {
        let fixture = Fixture::new();
        write(&fixture.proposal, completed());
        super::dependency_transaction::install(
            &fixture,
            event("tasks_0001", "COMPLETED", json!("2026-10-16T00:00:00")),
            |raw| {
                let mut target: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                if related {
                    target["sql"] = json!(
                        "UPDATE tasks_0001 SET payload='{\"status\":{\"status\":\"COMPLETED\",\"completedAt\":\"2026-10-16T00:01:00\"},\"progress\":7}', updated_at='2026-10-16 00:00:00' WHERE tasks_0001.id=7"
                    );
                } else {
                    target["sql"] = json!("DELETE FROM tasks_0001 WHERE id=7");
                }
                serde_json::to_vec(&target).unwrap()
            },
        );
        fixture.confirm();
        let report = fixture.evidence();
        assert!(
            report.facts["source_entry"]["locations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["physical_fields"]["fields"]
                    .as_array()
                    .is_some_and(|fields| fields.iter().any(|field| field["column"] == "payload")))
        );
        assert_eq!(report.facts["requires_genuine_replay"], true);
        assert!(
            report.facts["source_entry"]["locations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["protected_sql_value_pointers"]["value"]
                    == "/sql_values/<sql-token-index>/value")
        );
    }
}
