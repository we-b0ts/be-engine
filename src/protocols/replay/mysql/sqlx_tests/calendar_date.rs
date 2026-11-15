use super::*;
use sqlx::Executor;

#[tokio::test]
async fn mysql_calendar_date_over_tls_keeps_state_and_finite_consumption() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let source_time = "2026-10-20T15:01:00Z";
        let target_time = chrono::DateTime::parse_from_rfc3339("2026-10-21T19:13:00Z").unwrap().with_timezone(&Utc);
        let read_sql = "SELECT payload FROM pets WHERE id=7";
        let write_sql = "UPDATE pets SET payload=?, updated_at=? WHERE id=?";
        let initial = json!({"spec":{"lastActiveDate":"2026-10-20","currentStreak":36,"experience":562238},"stable":7});
        let mut source_updated = initial.clone();
        source_updated["spec"]["experience"] = json!(562240);
        let mut read = exchange(read_sql,result(json!([{"name":"payload","family":"string","sql_type":"VARCHAR"}]), json!([[{"kind":"string","value":initial.to_string()}]])));
        let mut write = exchange(write_sql,json!({"status":"ok","affected_rows":1}));
        write["command"] = json!("COM_STMT_EXECUTE");
        write["params"] = json!([{"kind":"string","value":source_updated.to_string()},{"kind":"string","value":"2026-10-20 23:01:00"},{"kind":"integer","value":7}]);
        let connection = uuid::Uuid::new_v4();
        for (i,event) in [&mut read,&mut write].into_iter().enumerate() {
            event["timestamp"] = json!(source_time);
            event["duration_ms"] = json!(0);
            event["connection_id"] = json!(connection);
            event["query_sequence"] = json!(i+1);
        }
        let policy = format!(r#"format: traffic-policy/v3
json:
  fields:
    /spec/lastActiveDate: {{kind: time, formats: [{{format: calendar_date, utc_offset: '+08:00'}}]}}
rules:
- id: updated-at
  match:
    api: GET /users
    resource: {{protocol: mysql, endpoint: '127.0.0.1:3306', database: appdb, username: root}}
    operation: COM_STMT_EXECUTE
    sql: {write_sql:?}
  effect:
    kind: mysql_values
    values:
      1: {{relative_time: sql_datetime}}
  proof: {{source: 'pets.py:updated_at', fact: 'Source samples the independent write request clock for updated_at'}}
"#);
        let (temp,addr,runtime,task) = fixture_with_policy(&[read,write],Some(&policy)).await;
        let recording = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
        let original = std::fs::read(&recording).unwrap();
        runtime.state.lock().await.protocols.mysql.observed_at_for_test = Some(target_time);
        let mut client = connect(addr,&temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        assert!((&mut client).fetch_one("SELECT payload FROM pets WHERE id=8").await.is_err());
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let row = (&mut client).fetch_one(read_sql).await.unwrap();
        let mut value: Value = serde_json::from_str(row.get::<&str,_>("payload")).unwrap();
        assert_eq!(value["spec"]["lastActiveDate"],"2026-10-22");
        assert_eq!(value["spec"]["experience"],562238);
        assert_eq!(value["spec"]["currentStreak"],36);
        let mut wrong = value.clone();
        wrong["spec"]["experience"] = json!(562239);
        assert!(sqlx::query(write_sql).bind(wrong.to_string()).bind("2026-10-22 03:13:00").bind(7_i64).execute(&mut client).await.is_err());
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        value["spec"]["experience"] = json!(562240);
        let updated = sqlx::query(write_sql).bind(value.to_string()).bind("2026-10-22 03:13:00").bind(7_i64).execute(&mut client).await.unwrap();
        assert_eq!(updated.rows_affected(),1);
        assert!(sqlx::query(write_sql).bind(value.to_string()).bind("2026-10-22 03:13:00").bind(7_i64).execute(&mut client).await.is_err());
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.protocols.mysql.events.matched_query_count,2);
        assert_eq!(state.protocols.mysql.events.unmatched_queries.len(),3);
        assert_eq!(std::fs::read(recording).unwrap(),original);
        task.abort();
    }).await.unwrap();
}
