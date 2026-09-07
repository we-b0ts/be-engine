use super::*;
use sqlx::Executor;

const TEMPLATE: &str = "UPDATE api_keys SET last_used_at=?, updated_at=now() WHERE api_keys.id=?";

fn policy(template: &str) -> String {
    format!(
        "version: 3\nexpected_response: assertions_only\ndependency_rules:\n  - id: key-last-use\n    protocol: mysql\n    case: {{method: GET, path: /users}}\n    target: {{host: 127.0.0.1, port: 3306}}\n    mysql:\n      command: COM_QUERY\n      database: appdb\n      username: root\n      sql: {template:?}\n      sql_values:\n        0:\n          source_evidence: 'security.py:get_auth_context assigns datetime.utcnow() before commit'\n          time:\n            relative_to: replay_now\n            tolerance: 5s\n            format: '%Y-%m-%d %H:%M:%S%.f'\n            timezone: '+00:00'\n"
    )
}

#[tokio::test]
async fn dynamic_sql_time_matches_text_and_prepared_writes_without_consuming_wrong_values() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for source_prepared in [false, true] {
            for target_mode in 0..3 {
                let mut write = exchange("UPDATE api_keys SET last_used_at='2020-01-01 06:20:38.340150', updated_at=now() WHERE api_keys.id=7",json!({"status":"ok","affected_rows":1}));
                if source_prepared {
                    write["command"] = json!("COM_STMT_EXECUTE");
                    write["sql"] = json!(TEMPLATE);
                    write["params"] = json!([{"kind":"datetime","value":"2020-01-01 06:20:38.340150"},{"kind":"integer","value":7}]);
                }
                let records = [write, exchange("COMMIT", json!({"status":"ok"}))];
                let (temp,addr,runtime,task) = fixture_with_policy(&records,Some(&policy(TEMPLATE))).await;
                let path = temp.path().join("case-id/dependencies.jsonl");
                let original = std::fs::read(&path).unwrap();
                let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
                for attempt in 0..4 {
                    let now = chrono::Utc::now().naive_utc();
                    let timestamp = if attempt == 0 { "2020-01-01 06:20:38.340150".to_owned() } else { now.format("%Y-%m-%d %H:%M:%S%.6f").to_string() };
                    let id = if attempt == 1 { 8_i64 } else { 7 };
                    let sql = format!("UPDATE api_keys SET last_used_at='{timestamp}', updated_at=now() WHERE api_keys.id={id}");
                    let result = match target_mode {
                        0 => (&mut client).execute(sql.as_str()).await,
                        1 => sqlx::query(&sql).execute(&mut client).await,
                        _ => sqlx::query(TEMPLATE).bind(chrono::NaiveDateTime::parse_from_str(&timestamp,"%Y-%m-%d %H:%M:%S%.f").unwrap()).bind(id).execute(&mut client).await,
                    };
                    if attempt == 2 { assert_eq!(result.unwrap().rows_affected(),1); }
                    else { assert!(result.is_err(),"stale time, changed key and exhausted evidence must fail"); }
                }
                (&mut client).execute("COMMIT").await.unwrap();
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.mysql.events.matched_query_count,2);
                assert_eq!(state.mysql.events.unmatched_queries.len(),3);
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                let report = state.replay_policy.as_ref().unwrap().report();
                assert_eq!(report.dependency_rules[0].time_validations,1);
                assert_eq!(report.dependency_rules[0].matches,1);
                assert!(report.unused_applicable_dependency_rule_ids.is_empty());
                assert_eq!(std::fs::read(path).unwrap(),original);
                task.abort();
            }
        }
    }).await.expect("dynamic SQL time replay timed out");
}

#[tokio::test]
async fn dynamic_sql_time_preserves_recorded_errors_and_stable_sql() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let write = exchange("UPDATE api_keys SET last_used_at='2020-01-01 00:00:00', updated_at=now() WHERE api_keys.id=7", json!({"status":"error","error_code":1213,"error_message":"deadlock"}));
        let (temp,addr,runtime,task) = fixture_with_policy(&[write],Some(&policy(TEMPLATE))).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let now = chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        for template in [TEMPLATE.replace("api_keys", "other_keys"), TEMPLATE.replace("updated_at=now()", "updated_at=NULL"), TEMPLATE.replace("WHERE api_keys.id=?", "WHERE api_keys.id=? OR 1=1")] {
            assert!(sqlx::query(&template).bind(&now).bind(7_i64).execute(&mut client).await.is_err());
        }
        let error = sqlx::query(TEMPLATE).bind(&now).bind(7_i64).execute(&mut client).await.unwrap_err();
        assert_eq!(error.as_database_error().unwrap().downcast_ref::<sqlx::mysql::MySqlDatabaseError>().number(),1213);
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count,1);
        assert_eq!(state.mysql.events.unmatched_queries.len(),3);
        task.abort();
    }).await.unwrap();
}
