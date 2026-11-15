use super::*;
use sqlx::Executor;

const TEMPLATE: &str = "UPDATE api_keys SET last_used_at=?, updated_at=now() WHERE api_keys.id=?";
const JSON_TIME_TEMPLATE: &str = "UPDATE kinds SET json=?, updated_at=? WHERE id=?";

fn policy(template: &str) -> String {
    format!(
        "version: 3\nexpected_response: assertions_only\ndependency_rules:\n  - id: key-last-use\n    protocol: mysql\n    mysql:\n      database: appdb\n      sql: {template:?}\n      sql_values: {{0: {{time: replay_now, tolerance: 5s}}}}\n"
    )
}

#[tokio::test]
async fn table_time_templates_replay_shards_without_consuming_a_wrong_shard() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let template = "UPDATE {{table}} SET last_used_at=?, updated_at=now() WHERE {{table}}.id=?";
        let policy = policy(template).replace("      sql_values:", "      table_series: {prefix: subtasks_, start: 0, end: 1023, width: 4}\n      sql_values:");
        for source_prepared in [false, true] {
            for target_prepared in [false, true] {
                let sql = TEMPLATE.replace("api_keys", "subtasks_0155");
                let mut write = exchange("UPDATE subtasks_0155 SET last_used_at='2020-01-01 00:00:00.000000', updated_at=now() WHERE subtasks_0155.id=7", json!({"status":"ok","affected_rows":1}));
                if source_prepared {
                    write["command"] = json!("COM_STMT_EXECUTE");
                    write["sql"] = json!(sql);
                    write["params"] = json!([{"kind":"datetime","value":"2020-01-01 00:00:00.000000"},{"kind":"integer","value":7}]);
                }
                let (temp, addr, runtime, task) = fixture_with_policy(&[write], Some(&policy)).await;
                let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                let original = std::fs::read(&path).unwrap();
                let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                let now = chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S%.6f").to_string();
                for (attempt, table) in ["subtasks_0640", "subtasks_0155", "subtasks_0155"].into_iter().enumerate() {
                    let result = if target_prepared {
                        sqlx::query(&TEMPLATE.replace("api_keys",table)).bind(chrono::NaiveDateTime::parse_from_str(&now,"%Y-%m-%d %H:%M:%S%.f").unwrap()).bind(7_i64).execute(&mut client).await
                    } else {
                        let sql = format!("UPDATE {table} SET last_used_at='{now}', updated_at=now() WHERE {table}.id=7");
                        (&mut client).execute(sql.as_str()).await
                    };
                    if attempt == 1 { assert_eq!(result.unwrap().rows_affected(),1); }
                    else { assert!(result.is_err(), "wrong shard and exhausted evidence must fail");
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await; }
                }
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.protocols.mysql.events.matched_query_count,1);
                assert_eq!(state.protocols.mysql.events.unmatched_queries.len(),2);
                assert_eq!(std::fs::read(path).unwrap(),original);
                task.abort();
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn dynamic_sql_time_matches_text_and_prepared_writes_without_consuming_wrong_values() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for source_prepared in [false, true] {
            for target_mode in 0..3 {
                let mut write = exchange("UPDATE api_keys SET last_used_at='2020-01-01 00:00:00.340150', updated_at=now() WHERE api_keys.id=7",json!({"status":"ok","affected_rows":1}));
                if source_prepared {
                    write["command"] = json!("COM_STMT_EXECUTE");
                    write["sql"] = json!(TEMPLATE);
                    write["params"] = json!([{"kind":"datetime","value":"2020-01-01 00:00:00.340150"},{"kind":"integer","value":7}]);
                }
                let records = [write, exchange("COMMIT", json!({"status":"ok"}))];
                let (temp,addr,runtime,task) = fixture_with_policy(&records,Some(&policy(TEMPLATE))).await;
                let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                let original = std::fs::read(&path).unwrap();
                let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
                for attempt in 0..4 {
                    let now = chrono::Utc::now().naive_utc();
                    let timestamp = if attempt == 0 { "2020-01-01 00:00:00.340150".to_owned() } else { now.format("%Y-%m-%d %H:%M:%S%.6f").to_string() };
                    let id = if attempt == 1 { 8_i64 } else { 7 };
                    let sql = format!("UPDATE api_keys SET last_used_at='{timestamp}', updated_at=now() WHERE api_keys.id={id}");
                    let result = match target_mode {
                        0 => (&mut client).execute(sql.as_str()).await,
                        1 => sqlx::query(&sql).execute(&mut client).await,
                        _ => sqlx::query(TEMPLATE).bind(chrono::NaiveDateTime::parse_from_str(&timestamp,"%Y-%m-%d %H:%M:%S%.f").unwrap()).bind(id).execute(&mut client).await,
                    };
                    if attempt == 2 {
                        if let Err(error) = &result {
                            let state = runtime.state.lock().await;
                            panic!("valid time failed: source_prepared={source_prepared}, target_mode={target_mode}, attempt={attempt}, error={error:?}, source={:?}, target={:?}, warnings={:?}", state.protocols.mysql.exchanges[0].record, state.protocols.mysql.events.unmatched_queries.last(), state.protocols.mysql.events.metadata_warnings);
                        }
                        assert_eq!(result.unwrap().rows_affected(),1);
                    }
                    else { assert!(result.is_err(),"stale time, changed key and exhausted evidence must fail: source_prepared={source_prepared}, target_mode={target_mode}, attempt={attempt}");
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await; }
                }
                (&mut client).execute("COMMIT").await.unwrap();
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.protocols.mysql.events.matched_query_count,2);
                assert_eq!(state.protocols.mysql.events.unmatched_queries.len(),3);
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
        let write = exchange("UPDATE api_keys SET last_used_at='2020-01-01 00:00:00.000000', updated_at=now() WHERE api_keys.id=7", json!({"status":"error","error_code":1213,"error_message":"deadlock"}));
        let (temp,addr,runtime,task) = fixture_with_policy(&[write],Some(&policy(TEMPLATE))).await;
        let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let now = chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S%.6f").to_string();
        for template in [TEMPLATE.replace("api_keys", "other_keys"), TEMPLATE.replace("updated_at=now()", "updated_at=NULL"), TEMPLATE.replace("WHERE api_keys.id=?", "WHERE api_keys.id=? OR 1=1")] {
            assert!(sqlx::query(&template).bind(&now).bind(7_i64).execute(&mut client).await.is_err());
            client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        }
        let error = sqlx::query(TEMPLATE).bind(&now).bind(7_i64).execute(&mut client).await.unwrap_err();
        assert_eq!(error.as_database_error().unwrap().downcast_ref::<sqlx::mysql::MySqlDatabaseError>().number(),1213);
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.protocols.mysql.events.matched_query_count,1);
        assert_eq!(state.protocols.mysql.events.unmatched_queries.len(),3);
        task.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn dynamic_sql_time_matches_scalar_and_nested_json_fields_atomically() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let recorded_json = r#"{"name":"stable","spec":{"cloudConfig":{"nevisIpObservedAt":"2020-01-01T00:00:00.000000+00:00"}}}"#;
        let mut write = exchange(
            JSON_TIME_TEMPLATE,
            json!({"status":"ok","affected_rows":1}),
        );
        write["command"] = json!("COM_STMT_EXECUTE");
        write["params"] = json!([
            {"kind":"string","value":recorded_json},
            {"kind":"datetime","value":"2020-01-01 00:00:00.000000"},
            {"kind":"integer","value":7}
        ]);
        let policy = format!(
            "version: 3\nexpected_response: assertions_only\ndependency_rules:\n  - id: kind-times\n    protocol: mysql\n    mysql:\n      database: appdb\n      sql: {JSON_TIME_TEMPLATE:?}\n      sql_values:\n        0:\n          json:\n            /spec/cloudConfig/nevisIpObservedAt: {{time: replay_now, tolerance: 5s, format: \"%+\"}}\n        1: {{time: replay_now, tolerance: 5s}}\n"
        );
        let (temp, addr, runtime, task) =
            fixture_with_policy(&[write], Some(&policy)).await;
        let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
        let original = std::fs::read(&path).unwrap();
        let mut client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;
        let now = chrono::Utc::now();
        let observed_at = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        let updated_at = now.naive_utc();

        let changed = json!({
            "name":"changed",
            "spec":{"cloudConfig":{"nevisIpObservedAt":observed_at.clone()}}
        })
        .to_string();
        assert!(
            sqlx::query(JSON_TIME_TEMPLATE)
                .bind(changed)
                .bind(updated_at)
                .bind(7_i64)
                .execute(&mut client)
                .await
                .is_err()
        );
        client = connect(addr, &temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")).await;

        let matching = json!({
            "spec":{"cloudConfig":{"nevisIpObservedAt":observed_at}},
            "name":"stable"
        })
        .to_string();
        assert_eq!(
            sqlx::query(JSON_TIME_TEMPLATE)
                .bind(matching)
                .bind(updated_at)
                .bind(7_i64)
                .execute(&mut client)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        client.close().await.unwrap();

        let state = runtime.state.lock().await;
        assert_eq!(state.protocols.mysql.events.matched_query_count, 1);
        assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
        let report = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(report.dependency_rules[0].time_validations, 2);
        assert_eq!(report.dependency_rules[0].matches, 1);
        assert_eq!(std::fs::read(path).unwrap(), original);
        task.abort();
    })
    .await
    .unwrap();
}
