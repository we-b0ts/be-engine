//! SQLAlchemy savepoint recordings exercised by real SQLx clients over TLS.
use super::*;

fn source() -> Vec<Value> {
    let statements = [
        ("SET AUTOCOMMIT=0", 2, 0),
        ("SELECT id FROM users WHERE id=1", 0, 1),
        ("SAVEPOINT sa_savepoint_1", 1, 1),
        ("UPDATE users SET active=1 WHERE id=1", 1, 1),
        ("RELEASE SAVEPOINT sa_savepoint_1", 1, 1),
        ("UPDATE users SET active=2 WHERE id=1", 1, 1),
        ("SAVEPOINT sa_savepoint_2", 1, 1),
        ("UPDATE users SET active=3 WHERE id=1", 1, 1),
        ("ROLLBACK TO SAVEPOINT sa_savepoint_2", 1, 1),
        ("SAVEPOINT sa_savepoint_3", 1, 1),
        ("UPDATE users SET active=4 WHERE id=1", 1, 1),
        ("RELEASE SAVEPOINT sa_savepoint_3", 1, 1),
        ("COMMIT", 1, 0),
    ];
    statements.into_iter().enumerate().map(|(index, (sql, before, after))| {
        let mut value = exchange(sql, json!({"status":"ok", "affected_rows":0, "last_insert_id":0, "server_status":after}));
        value["connection_id"] = json!(Uuid::from_u128(901));
        value["query_sequence"] = json!(index + 1);
        value["server_status_before"] = json!(before);
        if index == 1 {
            value["response"] = json!({"status":"resultset", "server_status":after,
                "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":1}]]});
        }
        value
    }).collect()
}

async fn write(tx: &mut sqlx::Transaction<'_, sqlx::MySql>, value: i32) {
    sqlx::query("UPDATE users SET active=? WHERE id=1")
        .bind(value)
        .execute(&mut **tx)
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlx_savepoint_names_and_retry_depth_preserve_one_outer_transaction() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for policy in [false, true] {
            let values = source();
            let (temp, addr, runtime, task) = fixture(&values, policy).await;
            let ca = temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
            let mut client = connect(addr, &ca).await;
            sqlx::query("SELECT id FROM users WHERE id=?")
                .bind(1_i32)
                .fetch_one(&mut client)
                .await
                .unwrap();
            let mut outer = client.begin().await.unwrap();
            let mut first = outer.begin().await.unwrap();
            write(&mut first, 1).await;
            first.commit().await.unwrap();
            write(&mut outer, 2).await;
            let mut failed = outer.begin().await.unwrap();
            write(&mut failed, 3).await;
            failed.rollback().await.unwrap();
            let mut retry = outer.begin().await.unwrap();
            write(&mut retry, 4).await;
            retry.commit().await.unwrap();
            outer.commit().await.unwrap();
            let state = runtime.state.lock().await;
            assert!(
                state.mysql.events.unmatched_queries.is_empty(),
                "{:?}",
                state.mysql.events.unmatched_queries
            );
            assert!(
                state.unused_exchanges(ReplaySource::Case).is_empty(),
                "{:?}",
                state.unused_exchanges(ReplaySource::Case)
            );
            assert_eq!(state.transaction_equivalent_autocommit().len(), 1);
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_savepoint_reference_on_another_socket_or_after_release_is_rejected() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let values = source();
        let (temp, addr, runtime, task) = fixture(&values, false).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut client = connect(addr, &ca).await;
        sqlx::query("SELECT id FROM users WHERE id=?")
            .bind(1_i32)
            .fetch_one(&mut client)
            .await
            .unwrap();
        let mut outer = client.begin().await.unwrap();
        sqlx::raw_sql("SAVEPOINT target_name")
            .execute(&mut *outer)
            .await
            .unwrap();
        let mut foreign_client = connect(addr, &ca).await;
        let mut foreign = foreign_client.begin().await.unwrap();
        assert!(
            sqlx::raw_sql("RELEASE SAVEPOINT target_name")
                .execute(&mut *foreign)
                .await
                .is_err()
        );
        write(&mut outer, 1).await;
        sqlx::raw_sql("RELEASE SAVEPOINT target_name")
            .execute(&mut *outer)
            .await
            .unwrap();
        assert!(
            sqlx::raw_sql("ROLLBACK TO SAVEPOINT target_name")
                .execute(&mut *outer)
                .await
                .is_err()
        );
        assert!(runtime.state.lock().await.mysql.case_is_dirty("case-id"));
        task.abort();
    })
    .await
    .unwrap();
}
