use super::*;

#[test]
fn sql_time_table_template_preserves_physical_routing_and_stable_values() {
    let fixture = policy_fixture(
        r#"
version: 3
expected_response: assertions_only
dependency_rules:
- id: subtask-times
  protocol: mysql
  mysql:
    database: pluto_audit
    sql: UPDATE {{table}} SET updated_at=? WHERE {{table}}.id = ?
    table_series: {prefix: subtasks_, start: 0, end: 1023, width: 4}
    sql_values: {0: {time: replay_now, tolerance: 5s}}
"#,
    );
    let runtime = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    let now = Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 1).unwrap();
    anchor_sql_times(&runtime, now);
    for table in ["subtasks_0000", "subtasks_0155", "subtasks_1023"] {
        let source = format!(
            "UPDATE {table} SET updated_at='2020-01-01 00:00:00.123456' WHERE {table}.id = 7"
        );
        let prepared = format!("UPDATE {table} SET updated_at=? WHERE {table}.id = ?");
        let target = format!(
            "UPDATE {table} SET updated_at='2026-09-07 12:00:01.123456' WHERE {table}.id = 7"
        );
        let source_params = values(&[json!("2020-01-01 00:00:00.123456"), json!(7)]);
        let target_params = values(&[json!("2026-09-07 12:00:01.123456"), json!(7)]);
        for reverse in [false, true] {
            let context = MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: if reverse {
                    "COM_QUERY"
                } else {
                    "COM_STMT_EXECUTE"
                },
                recorded_sql: Some(if reverse { &prepared } else { &source }),
                sql: Some(if reverse { &target } else { &prepared }),
                recorded: reverse.then_some(source_params.as_slice()),
                actual: (!reverse).then_some(target_params.as_slice()),
            };
            assert!(runtime.preview_mysql_sql_values(&context).unwrap().is_ok());
            let prepare = MysqlPolicyContext {
                command: "COM_STMT_EXECUTE",
                sql: Some(&prepared),
                actual: None,
                ..context
            };
            assert!(runtime.mysql_sql_values_metadata_matches(&prepare));
        }
        for mutation in ["other_shard", "qualifier", "stable_id", "stale_time"] {
            let actual = match mutation {
                "other_shard" => target.replace(table, "subtasks_0001"),
                "qualifier" => target.replace(&format!("{table}.id"), "subtasks_0001.id"),
                "stable_id" => target.replace(" = 7", " = 8"),
                "stale_time" => target.replace("2026-09-07", "2020-01-01"),
                _ => unreachable!(),
            };
            let context = MysqlPolicyContext {
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_QUERY",
                recorded_sql: Some(&source),
                sql: Some(&actual),
                recorded: None,
                actual: None,
            };
            assert!(
                !runtime
                    .preview_mysql_sql_values(&context)
                    .is_some_and(|r| r.is_ok()),
                "{table}: {mutation}"
            );
        }
    }
    for table in ["subtasks_1024", "tasks_0155", "subtasks_155"] {
        let sql = format!("UPDATE {table} SET updated_at=? WHERE {table}.id = ?");
        let context = MysqlPolicyContext {
            case_id: Some(CASE_ID),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some(&sql),
            sql: Some(&sql),
            recorded: None,
            actual: None,
        };
        assert!(runtime.preview_mysql_sql_values(&context).is_none());
    }
}
