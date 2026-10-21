use super::*;

fn completed() -> serde_json::Value {
    json!({"id":"completed","surface":"dependency.request","match":{"api":"GET /api","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY","sql":"UPDATE {{table}} SET payload=?, updated_at=? WHERE {{table}}.id=?","table_series":{"prefix":"tasks_","start":1,"end":2,"width":4}},
        "slot":{"sql_value":0},"codec":"json","contract":{"/status/completedAt":{"kind":"conditional","when":{"relative_pointer":"../status","equals":"COMPLETED"},"contract":{"relative_time":"iso8601_naive","clock_group":"completed"}}},
        "proof":{"source":"tasks.py:complete","fact":"Source sets completion time in the terminal branch; RUNNING null and all business fields remain exact"}})
}

fn updated() -> serde_json::Value {
    let mut rule = completed();
    rule["id"] = json!("updated");
    for key in ["surface", "slot", "codec", "contract"] {
        rule.as_object_mut().unwrap().remove(key);
    }
    rule["effect"] = json!({"kind":"mysql_values","values":{"1":{"relative_time":"sql_datetime","clock_group":"updated"}}});
    rule
}

fn event(table: &str, status: &str, completed: serde_json::Value) -> serde_json::Value {
    let payload =
        json!({"status":{"status":status,"completedAt":completed},"progress":7}).to_string();
    json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "connection_id":uuid::Uuid::nil(),"query_sequence":1,"target_host":"db.test","target_port":3306,"database":"app","username":"writer","command":"COM_QUERY",
        "sql":format!("UPDATE {table} SET payload='{payload}', updated_at='2026-10-16 00:00:00' WHERE {table}.id=7"),"response":{"status":"ok"},"outcome":"response","parse_warnings":[]})
}

#[test]
fn sql_value_table_series_public_plan_apply_keeps_nullable_conditions_and_exact_statements() {
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
            let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
                write(
                    &root.join(".traffic-e2e/policy.yaml"),
                    json!({"format":"traffic-policy/v1","rules":[updated()]}),
                );
                vec![]
            });
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
                    target["params"] = json!([{"kind":"string","value":payload},{"kind":"string","value":"2026-10-16 00:01:00"},{"kind":"integer","value":7}]);
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
                    1
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
                        0
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
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v1","rules":[completed()]}),
            );
            vec![]
        });
        write(&fixture.proposal, completed());
        super::dependency_transaction::install(
            &fixture,
            event("tasks_0001", "COMPLETED", json!("2026-10-16T00:00:00")),
            |raw| {
                let mut target: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                if related {
                    target["sql"] = json!(
                        "UPDATE tasks_0001 SET payload='{\"status\":{\"status\":\"COMPLETED\",\"completedAt\":\"2026-10-16T00:01:00\"},\"progress\":7}', updated_at='2026-10-16 00:01:00' WHERE tasks_0001.id=7"
                    );
                } else {
                    target["sql"] = json!("DELETE FROM tasks_0001 WHERE id=7");
                }
                serde_json::to_vec(&target).unwrap()
            },
        );
        fixture.confirm();
        let state = fixture.state();
        let query = evidence::commands(fixture.root(), &state)
            .into_iter()
            .find(|query| query.query_id.ends_with("unified-rule-candidates"))
            .unwrap();
        let report = evidence::query(fixture.root(), &state, &query.query_id).unwrap();
        assert!(
            report.facts["source_entry"]["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["binding"]["slot"]["sql_value"] == 0)
        );
        assert_eq!(report.facts["requires_genuine_replay"], true);
    }
}
