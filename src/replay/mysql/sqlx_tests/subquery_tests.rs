//! Exact subquery compatibility with inline, bound and mixed prepared values.
use super::*;
use sqlx::{Column, Executor};

const TEMPLATE: &str = "SELECT count(*) AS total FROM subtasks WHERE task_id=? AND task_id IN (SELECT tasks.id FROM tasks WHERE tasks.user_id=?) AND role='ASSISTANT' AND status='FAILED'";
fn inline(task: &str, user: &str) -> String {
    TEMPLATE.replacen('?', task, 1).replacen('?', user, 1)
}
async fn query(
    client: &mut MySqlConnection,
    mode: u8,
    task: i64,
    user: i64,
) -> sqlx::Result<Vec<sqlx::mysql::MySqlRow>> {
    let sql = inline(&task.to_string(), &user.to_string());
    match mode {
        0 => client.fetch_all(sql.as_str()).await,
        1 => {
            sqlx::query(TEMPLATE)
                .bind(task)
                .bind(user)
                .fetch_all(client)
                .await
        }
        2 => sqlx::query(&sql).fetch_all(client).await,
        _ => {
            sqlx::query(&TEMPLATE.replacen('?', &task.to_string(), 1))
                .bind(user)
                .fetch_all(client)
                .await
        }
    }
}

#[tokio::test]
async fn subquery_reads_bind_identical_values_across_all_wire_forms_without_rules() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for source_mode in 0..3 {
            for target_mode in 0..4 {
                for policy in [false, true] {
                    let mut source = exchange(
                        &inline("7", "42"),
                        result(
                            json!([{"name":"total","family":"integer","sql_type":"BIGINT"}]),
                            json!([[{"kind":"integer","value":13}]]),
                        ),
                    );
                    if source_mode != 0 {
                        source["command"] = json!("COM_STMT_EXECUTE");
                    }
                    if source_mode == 1 {
                        source["sql"] = json!(TEMPLATE);
                        source["params"] =
                            json!([{"kind":"integer","value":7},{"kind":"integer","value":42}]);
                    } else if source_mode == 2 {
                        source["params"] = json!([]);
                    }
                    let (temp, addr, runtime, task) = fixture(&[source], policy).await;
                    let path = temp.path().join("case-id/dependencies.jsonl");
                    let immutable = std::fs::read(&path).unwrap();
                    let mut client =
                        connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
                    // Failed matches must leave the sole recorded query available.
                    for (id, user) in [(8, 42), (7, 43)] {
                        assert!(query(&mut client, target_mode, id, user).await.is_err());
                    }
                    let rows = query(&mut client, target_mode, 7, 42).await.unwrap();
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].get::<i64, _>("total"), 13);
                    assert_eq!(rows[0].columns()[0].name(), "total");
                    assert!(query(&mut client, target_mode, 7, 42).await.is_err());
                    client.close().await.unwrap();
                    let state = runtime.state.lock().await;
                    assert_eq!(state.mysql.events.matched_query_count, 1);
                    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                    assert_eq!(std::fs::read(path).unwrap(), immutable);
                    task.abort();
                }
            }
        }
    })
    .await
    .expect("subquery protocol replay timed out");
}

#[tokio::test]
async fn subquery_prepared_rebinding_preserves_types_predicates_and_recorded_errors() {
    let mut source = exchange(
        TEMPLATE,
        json!({"status":"error","error_code":1213,"error_message":"deadlock"}),
    );
    source["command"] = json!("COM_STMT_EXECUTE");
    source["params"] = json!([{"kind":"integer","value":7},{"kind":"integer","value":42}]);
    let (temp, addr, runtime, task) = fixture(&[source], true).await;
    let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
    for bad in [
        inline("'7'", "42"),
        inline("7", "42").replace("'FAILED'", "'RUNNING'"),
        inline("7", "42").replace("FROM tasks", "FROM other_tasks"),
        inline("7", "42").replace(" AND task_id IN", " OR task_id IN"),
    ] {
        let error = sqlx::query(&bad).fetch_all(&mut client).await.unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .unwrap()
                .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .number(),
            1105
        );
    }
    let error = query(&mut client, 2, 7, 42).await.unwrap_err();
    assert_eq!(
        error
            .as_database_error()
            .unwrap()
            .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
            .number(),
        1213
    );
    assert_eq!(
        runtime.state.lock().await.mysql.events.matched_query_count,
        1
    );
    task.abort();
}
