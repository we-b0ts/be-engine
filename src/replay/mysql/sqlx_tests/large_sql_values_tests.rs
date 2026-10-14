//! Large recorded JSON literals with ordinary SQLx text/prepared clients over TLS.
use super::*;
use sqlx::Executor;

const SQL: &str =
    "UPDATE entries_0031 SET json=?, is_active=?, updated_at=? WHERE entries_0031.id=?";

fn text_sql(payload: &str, timestamp: &str, id: i64) -> String {
    format!(
        "UPDATE entries_0031 SET json='{payload}', is_active=0, updated_at='{timestamp}' WHERE entries_0031.id={id}"
    )
}

#[tokio::test]
async fn large_sql_value_literals_replay_json_times_and_preserve_stable_values_and_consumption() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let policy = r#"
version: 3
expected_response: assertions_only
dependency_rules:
- id: large-json-time
  protocol: mysql
  mysql:
    database: appdb
    sql: UPDATE {{table}} SET json=?, is_active=?, updated_at=? WHERE {{table}}.id=?
    table_series: {prefix: entries_, start: 0, end: 1023, width: 4}
    sql_values:
      0:
        json:
          /status/updatedAt: {time: replay_now, tolerance: 5s, format: "%+"}
      2: {time: replay_now, tolerance: 5s}
"#;
        let recorded_payload = json!({
            "name":"stable", "data":"x".repeat(300_000),
            "status":{"updatedAt":"2020-01-01T00:00:00+00:00"}
        })
        .to_string();
        let recorded_sql = text_sql(&recorded_payload, "2020-01-01 00:00:00", 7);
        assert!(recorded_sql.len() > 256 * 1024 && recorded_sql.len() < 1024 * 1024);
        for source_prepared in [false, true] {
            for target_prepared in [false, true] {
                let mut write = exchange(&recorded_sql, json!({"status":"ok","affected_rows":1}));
                if source_prepared {
                    write["command"] = json!("COM_STMT_EXECUTE");
                    write["sql"] = json!(SQL);
                    write["params"] = json!([
                        {"kind":"string","value":recorded_payload},
                        {"kind":"integer","value":0},
                        {"kind":"datetime","value":"2020-01-01 00:00:00"},
                        {"kind":"integer","value":7}
                    ]);
                }
                let (temp, addr, runtime, task) = fixture_with_policy(&[write], Some(policy)).await;
                let path = temp.path().join("case-id/dependencies.jsonl");
                let original = std::fs::read(&path).unwrap();
                let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
                // Wrong stable JSON, key, and stale time cannot consume evidence.
                // A correct call succeeds once in each text/prepared combination.
                for attempt in 0..5 {
                    let now = chrono::Utc::now();
                    let timestamp = now.naive_utc().format("%Y-%m-%d %H:%M:%S%.6f").to_string();
                    let observed = if attempt == 2 {
                        "2020-01-01T00:00:00+00:00".to_string()
                    } else {
                        now.to_rfc3339()
                    };
                    let payload = json!({
                        "name":if attempt == 0 {"changed"} else {"stable"},
                        "data":"x".repeat(300_000), "status":{"updatedAt":observed}
                    })
                    .to_string();
                    let id = if attempt == 1 { 8_i64 } else { 7 };
                    let result = if target_prepared {
                        sqlx::query(SQL)
                            .bind(&payload)
                            .bind(0_i64)
                            .bind(&timestamp)
                            .bind(id)
                            .execute(&mut client)
                            .await
                    } else {
                        (&mut client)
                            .execute(text_sql(&payload, &timestamp, id).as_str())
                            .await
                    };
                    if attempt == 3 {
                        assert_eq!(result.unwrap().rows_affected(), 1);
                    } else {
                        assert!(
                            result.is_err(),
                            "stable values, time and finite consumption remain strict"
                        );
                    }
                }
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.mysql.events.matched_query_count, 1);
                assert_eq!(state.mysql.events.unmatched_queries.len(), 4);
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                let report = state.replay_policy.as_ref().unwrap().report();
                assert_eq!(report.dependency_rules[0].time_validations, 2);
                assert_eq!(report.dependency_rules[0].matches, 1);
                assert_eq!(std::fs::read(path).unwrap(), original);
                task.abort();
            }
        }
    })
    .await
    .expect("large SQL value replay timed out");
}
