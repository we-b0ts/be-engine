use super::*;

#[tokio::test]
async fn sql_value_table_series_conditions_and_native_times_keep_strict_state_over_tls() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let source_time = "2026-10-16T00:00:00Z";
        let observed = chrono::DateTime::parse_from_rfc3339("2026-10-16T00:01:00Z").unwrap().with_timezone(&Utc);
        let body = |status:&str,completed:Value| json!({"status":{"status":status,"completedAt":completed},"progress":7});
        let sql = |table:&str| format!("UPDATE {table} SET payload=?, updated_at=? WHERE {table}.id=?");
        let mut events = Vec::new();
        let connection = uuid::Uuid::new_v4();
        for (i,(table,status,completed)) in [("tasks_0001","RUNNING",Value::Null),("tasks_0001","COMPLETED",json!("2026-10-16T00:00:00")),("tasks_0002","COMPLETED",json!("2026-10-16T00:00:00"))].into_iter().enumerate() {
            let mut event = exchange(&sql(table),json!({"status":"ok","affected_rows":1}));
            event["command"] = json!("COM_STMT_EXECUTE");event["timestamp"] = json!(source_time);event["duration_ms"] = json!(0);
            event["connection_id"] = json!(connection);event["query_sequence"] = json!(i+1);
            event["params"] = json!([{"kind":"string","value":body(status,completed).to_string()},{"kind":"string","value":"2026-10-16 00:00:00"},{"kind":"integer","value":7}]);events.push(event);
        }
        let policy = r#"format: traffic-policy/v3
json:
  fields:
    /status/completedAt: {kind: time, formats: [iso8601_naive]}
rules:
- id: updated
  match:
    api: GET /users
    resource: {protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}
    operation: COM_STMT_EXECUTE
    sql: UPDATE {{table}} SET payload=?, updated_at=? WHERE {{table}}.id=?
    table_series: {prefix: tasks_, start: 1, end: 2, width: 4}
  effect:
    kind: mysql_values
    values:
      1: {relative_time: sql_datetime, clock_group: updated}
  proof: {source: 'tasks.py:flush', fact: 'Row timestamp is an independent local flush-time sample'}
"#;
        let (temp,addr,runtime,task) = fixture_with_policy(&events,Some(policy)).await;
        let recording = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");let original=std::fs::read(&recording).unwrap();
        runtime.state.lock().await.mysql.observed_at_for_test = Some(observed);
        let mut client = connect(addr,&temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let invalid_running = body("RUNNING",json!("2026-10-16T00:01:00"));
        assert!(sqlx::query(&sql("tasks_0001")).bind(invalid_running.to_string()).bind("2026-10-16 00:01:00").bind(7_i64).execute(&mut client).await.is_err());
        let running=body("RUNNING",Value::Null);
        assert_eq!(sqlx::query(&sql("tasks_0001")).bind(running.to_string()).bind("2026-10-16 00:01:00").bind(7_i64).execute(&mut client).await.unwrap().rows_affected(),1);
        let good = body("COMPLETED",json!("2026-10-16T00:01:00"));
        let mut changed = good.clone();changed["progress"] = json!(8);
        for (statement,payload,id) in [
            (sql("tasks_0003"),good.clone(),7),
            (sql("tasks_1"),good.clone(),7),
            ("UPDATE tasks_0001 SET payload=?, updated_at=? WHERE tasks_0002.id=?".into(),good.clone(),7),
            (sql("tasks_0001"),good.clone(),8),
            (sql("tasks_0001"),changed,7),
            (sql("tasks_0001"),body("COMPLETED",Value::Null),7),
        ] {assert!(sqlx::query(&statement).bind(payload.to_string()).bind("2026-10-16 00:01:00").bind(id).execute(&mut client).await.is_err());}
        for table in ["tasks_0001","tasks_0002"] {assert_eq!(sqlx::query(&sql(table)).bind(good.to_string()).bind("2026-10-16 00:01:00").bind(7_i64).execute(&mut client).await.unwrap().rows_affected(),1);}
        assert!(sqlx::query(&sql("tasks_0001")).bind(good.to_string()).bind("2026-10-16 00:01:00").bind(7_i64).execute(&mut client).await.is_err());
        client.close().await.unwrap();let state=runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,3);assert_eq!(state.mysql.events.unmatched_queries.len(),8);
        assert_eq!(std::fs::read(recording).unwrap(),original);task.abort();
    }).await.unwrap();
}
