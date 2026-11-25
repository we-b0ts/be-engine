use super::*;

fn completed() -> serde_json::Value {
    json!({"format":"traffic-policy/v3","json":{"fields":{
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
