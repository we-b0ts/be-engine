//! Driver controls retain finite recorded failures before builtin responses.
use super::*;

async fn assert_recorded_control_failure(sql: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        for policy in [false, true] {
            let records = [
                exchange(
                    "SELECT id FROM unrelated_business WHERE id=7",
                    result(
                        json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                        json!([[{"kind":"integer","value":7}]]),
                    ),
                ),
                exchange(
                    sql,
                    json!({"status":"error","error_code":1644,
                        "error_message":"finite recorded control failure"}),
                ),
            ];
            let (temp, address, runtime, task) = fixture(&records, policy).await;
            let ca = temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
            let mut client = connect(address, &ca).await;
            assert_eq!(
                runtime.state.lock().await.mysql.events.matched_query_count,
                0
            );

            let error = sqlx::raw_sql(sql).execute(&mut client).await.unwrap_err();
            let database = error
                .as_database_error()
                .unwrap()
                .downcast_ref::<sqlx::mysql::MySqlDatabaseError>();
            assert_eq!(database.number(), 1644, "{sql}, policy={policy}");
            assert_eq!(database.message(), "finite recorded control failure");
            client.close().await.unwrap();

            let state = runtime.state.lock().await;
            assert!(state.mysql.exchanges[1].status.is_consumed());
            assert!(state.mysql.exchanges[0].status.is_available());
            assert_eq!(state.mysql.events.matched_query_count, 1);
            assert!(state.mysql.events.unmatched_queries.is_empty());
            assert!(state.mysql.events.builtin_queries.iter().all(|query| {
                query.sql.as_deref().map(normalize_sql) != Some(normalize_sql(sql))
            }));
            task.abort();
        }
    })
    .await
    .expect("recorded control failure test timed out");
}

#[tokio::test]
async fn recorded_begin_error_is_consumed_before_builtin_success() {
    assert_recorded_control_failure("BEGIN").await;
}

#[tokio::test]
async fn recorded_setup_error_is_consumed_before_builtin_success() {
    assert_recorded_control_failure("SET NAMES utf8mb4").await;
}
