//! Ordinary SQLx transactions prove implicit Source transaction coverage over TLS.
use super::*;

fn records() -> Vec<Value> {
    super::super::transaction_equivalence::tests::records()
}

async fn body(tx: &mut sqlx::Transaction<'_, sqlx::MySql>, value: i32) {
    let row = sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut **tx)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>(0), 1);
    sqlx::query("UPDATE users SET active=? WHERE id=?")
        .bind(value)
        .bind(1_i32)
        .execute(&mut **tx)
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlx_explicit_transactions_cover_one_persistent_source_autocommit_setting() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for policy in [false, true] {
            let values = records();
            let (temp, addr, runtime, task) = fixture(&values, policy).await;
            let path = temp.path().join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
            let original = std::fs::read(&path).unwrap();
            let ca = temp.path().join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
            let mut client = connect(addr, &ca).await;
            let mut tx = client.begin().await.unwrap();
            body(&mut tx, 1).await;
            assert_eq!(runtime.state.lock().await.unused_exchanges(ReplaySource::Case).iter()
                .filter(|e| e.query_sequence == Some(3)).count(), 1);
            tx.commit().await.unwrap();
            assert!(runtime.state.lock().await.transaction_equivalent_autocommit().is_empty());
            let mut tx = client.begin().await.unwrap();
            body(&mut tx, 2).await;
            tx.commit().await.unwrap();
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty(), "{:?}", state.unused_exchanges(ReplaySource::Case));
            assert!(state.mysql.events.unmatched_queries.is_empty());
            let covered = state.transaction_equivalent_autocommit();
            assert_eq!(covered.len(), 1);
            assert_eq!(covered[0].diagnostic.as_ref().unwrap()["covered_transaction_count"], 2);
            assert_eq!(serde_json::to_value(state.snapshot_report()).unwrap()["transaction_equivalent_mysql_autocommit_exchanges"].as_array().unwrap().len(), 1);
            assert_eq!(std::fs::read(path).unwrap(), original);
            task.abort();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn pooled_autocommit_writes_followed_by_commit_keep_the_original_dirty_setup() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = records();
        values.truncate(4);
        let (temp, addr, runtime, task) = fixture(&values, false).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        sqlx::query("SELECT id FROM users WHERE id=?")
            .bind(1_i32)
            .fetch_one(&mut client)
            .await
            .unwrap();
        sqlx::query("UPDATE users SET active=? WHERE id=?")
            .bind(1_i32)
            .bind(1_i32)
            .execute(&mut client)
            .await
            .unwrap();
        sqlx::raw_sql("COMMIT").execute(&mut client).await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.transaction_equivalent_autocommit().is_empty());
        let unused = state.unused_exchanges(ReplaySource::Case);
        assert_eq!(unused.len(), 1);
        assert_eq!(
            unused[0].diagnostic.as_ref().unwrap()["reason"],
            "target_transaction_missing"
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sqlx_explicit_rollback_covers_a_recorded_implicit_rollback() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = records();
        values.truncate(4);
        values[3]["sql"] = json!("ROLLBACK");
        let (temp, addr, runtime, task) = fixture(&values, false).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let mut tx = client.begin().await.unwrap();
        body(&mut tx, 1).await;
        tx.rollback().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert_eq!(state.transaction_equivalent_autocommit().len(), 1);
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn matching_all_business_sql_without_begin_or_commit_does_not_match_the_transaction() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for with_begin in [false, true] {
            let mut values = records();
            values.truncate(4);
            let (temp, addr, runtime, task) = fixture(&values, false).await;
            let mut client = connect(
                addr,
                &temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
            )
            .await;
            if with_begin {
                sqlx::raw_sql("BEGIN").execute(&mut client).await.unwrap();
            }
            sqlx::query("SELECT id FROM users WHERE id=?")
                .bind(1_i32)
                .fetch_one(&mut client)
                .await
                .unwrap();
            sqlx::query("UPDATE users SET active=? WHERE id=?")
                .bind(1_i32)
                .bind(1_i32)
                .execute(&mut client)
                .await
                .unwrap();
            let state = runtime.state.lock().await;
            assert_eq!(state.mysql.events.matched_query_count, 2);
            assert!(state.transaction_equivalent_autocommit().is_empty());
            let unused = state.unused_exchanges(ReplaySource::Case);
            assert_eq!(unused.len(), 2, "SET and COMMIT must both remain required");
            assert!(unused.iter().any(|e| e.query_sequence == Some(3)));
            assert!(unused.iter().any(|e| e.query_sequence == Some(7)));
            assert!(state.snapshot_report().is_dirty());
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sqlx_transaction_closures_can_reuse_distinct_pool_connections() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (temp, addr, runtime, task) = fixture(&records(), false).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        for value in [1_i32, 2] {
            let mut client = connect(addr, &ca).await;
            client
                .transaction(|connection| {
                    Box::pin(async move {
                        sqlx::query("SELECT id FROM users WHERE id=?")
                            .bind(1_i32)
                            .fetch_one(&mut **connection)
                            .await?;
                        sqlx::query("UPDATE users SET active=? WHERE id=?")
                            .bind(value)
                            .bind(1_i32)
                            .execute(&mut **connection)
                            .await?;
                        Ok::<_, sqlx::Error>(())
                    })
                })
                .await
                .unwrap();
            client.close().await.unwrap();
        }
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        let proof = state.transaction_equivalent_autocommit();
        assert_eq!(proof.len(), 1);
        let groups = &proof[0].diagnostic.as_ref().unwrap()["source_transactions"];
        assert_ne!(
            groups[0]["target_connection_id"],
            groups[1]["target_connection_id"]
        );
        task.abort();
    })
    .await
    .unwrap();
}
