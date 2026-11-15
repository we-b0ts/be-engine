use super::*;

#[test]
fn cached_time_templates_follow_policy_reload_and_recheck_bound_values() {
    let policy = |column: &str| {
        format!(
            "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: time\n  protocol: mysql\n  target: {{host: audit.example.test, port: 3306}}\n  mysql:\n    command: COM_STMT_EXECUTE\n    database: pluto_audit\n    sql: UPDATE {{{{table}}}} SET {column}=? WHERE id=?\n    table_series: {{prefix: tasks_, start: 0, end: 1023, width: 4}}\n    sql_values: {{0: {{time: preserve_relative}}}}\n"
        )
    };
    let fixture = policy_fixture(&policy("updated_at"));
    let original = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    crate::policy::runtime::write_policy_fixture(&fixture.policy_path, policy("completed_at"))
        .unwrap();
    let reloaded = ReplayPolicyRuntime::load(&fixture.policy_path, &fixture.cases).unwrap();
    let identity = mysql_identity();
    let now = Utc.with_ymd_and_hms(2026, 9, 7, 12, 0, 0).unwrap();
    for (runtime, column) in [(&original, "updated_at"), (&reloaded, "completed_at")] {
        anchor_sql_times(runtime, now);
        let recorded = format!("UPDATE tasks_0155 SET {column}='2020-01-01 00:00:00' WHERE id=7");
        let sql = format!("UPDATE tasks_0155 SET {column}=? WHERE id=?");
        for (time, id, passes) in [
            ("2026-09-07 12:00:00", 7, true),
            ("2026-09-07 12:00:00", 8, false),
            ("2026-09-07 12:00:06", 7, false),
            ("2026-09-07 12:00:01", 7, true),
        ] {
            let params = values(&[json!(time), json!(id)]);
            let context = MysqlPolicyContext {
                request_times: runtime.request_contracts.request_times(CASE_ID),
                case_id: Some(CASE_ID),
                identity: &identity,
                command: "COM_STMT_EXECUTE",
                recorded_sql: Some(&recorded),
                sql: Some(&sql),
                recorded: None,
                actual: Some(&params),
            };
            assert_eq!(
                runtime.preview_mysql_sql_values(&context).unwrap().is_ok(),
                passes
            );
        }
        let other = sql.replace(column, "unselected_column");
        let context = MysqlPolicyContext {
            request_times: runtime.request_contracts.request_times(CASE_ID),
            case_id: Some(CASE_ID),
            identity: &identity,
            command: "COM_STMT_EXECUTE",
            recorded_sql: Some(&recorded),
            sql: Some(&other),
            recorded: None,
            actual: None,
        };
        assert!(runtime.preview_mysql_sql_values(&context).is_none());
    }
}

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
                request_times: runtime.request_contracts.request_times(CASE_ID),
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
                request_times: runtime.request_contracts.request_times(CASE_ID),
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
                request_times: runtime.request_contracts.request_times(CASE_ID),
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
            request_times: runtime.request_contracts.request_times(CASE_ID),
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
