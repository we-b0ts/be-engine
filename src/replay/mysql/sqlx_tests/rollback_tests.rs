use super::*;

fn transaction_records() -> Vec<Value> {
    let connection = Uuid::new_v4();
    [
        "BEGIN",
        "UPDATE users SET active=0 WHERE id=1",
        "ROLLBACK",
        "ROLLBACK",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, sql)| {
        let mut record = exchange(
            sql,
            json!({"status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0}),
        );
        record["connection_id"] = json!(connection);
        record["query_sequence"] = json!(index + 10);
        record
    })
    .collect()
}

#[tokio::test]
async fn changing_business_rollback_to_commit_stays_dirty() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let records = transaction_records();
        let (temp, addr, runtime, task) = fixture(&records, false).await;
        let original = std::fs::read(temp.path().join("case-id/dependencies.jsonl")).unwrap();
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let mut tx = client.begin().await.unwrap();
        sqlx::query("UPDATE users SET active=0 WHERE id=1")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        {
            let state = runtime.state.lock().await;
            let unused = state.unused_exchanges(ReplaySource::Case);
            assert_eq!(unused.len(), 1);
            assert_eq!(unused[0].index, 2);
            assert_eq!(state.allowed_unused_rollbacks()[0].index, 3);
            assert_eq!(
                state.mysql.exchanges.len(),
                4,
                "cleanup evidence must not be discarded"
            );
        }
        assert_eq!(
            std::fs::read(temp.path().join("case-id/dependencies.jsonl")).unwrap(),
            original
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn real_business_rollback_does_not_require_repeated_pool_cleanup() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (temp, addr, runtime, task) = fixture(&transaction_records(), false).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let mut tx = client.begin().await.unwrap();
        sqlx::query("UPDATE users SET active=0 WHERE id=1")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        {
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.allowed_unused_rollbacks().len(), 1);
        }
        // A client that does issue the extra rollback still consumes the real evidence.
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut client)
            .await
            .unwrap();
        assert!(
            runtime
                .state
                .lock()
                .await
                .allowed_unused_rollbacks()
                .is_empty()
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn implicit_read_cleanup_can_be_omitted_or_consumed_without_discarding_reads() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let connection = Uuid::new_v4();
        let mut read = exchange(
            "SELECT id FROM users WHERE id=1",
            result(
                json!([{"name":"id","family":"integer","sql_type":"INT"}]),
                json!([[{"kind":"integer","value":1}]]),
            ),
        );
        read["server_status_before"] = json!(0);
        read["response"]["server_status"] = json!(1);
        let mut rollback = exchange(
            "ROLLBACK",
            json!({"status":"ok", "server_status":0,
            "affected_rows":0, "last_insert_id":0}),
        );
        rollback["server_status_before"] = json!(1);
        let mut records = vec![read, rollback.clone(), rollback];
        for (index, record) in records.iter_mut().enumerate() {
            record["connection_id"] = json!(connection);
            record["query_sequence"] = json!(116 + index);
        }
        let (temp, addr, runtime, task) = fixture(&records, true).await;
        let path = temp.path().join("case-id/dependencies.jsonl");
        let original = std::fs::read(&path).unwrap();
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        {
            let state = runtime.state.lock().await;
            assert_eq!(
                state.unused_exchanges(ReplaySource::Case).len(),
                1,
                "the read remains required"
            );
        }
        let row = sqlx::query("SELECT id FROM users WHERE id=?")
            .bind(1_i32)
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(row.get::<i32, _>("id"), 1);
        {
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.allowed_unused_rollbacks().len(), 2);
            assert_eq!(state.mysql.events.matched_query_count, 1);
        }
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut client)
            .await
            .unwrap();
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut client)
            .await
            .unwrap();
        assert!(
            runtime
                .state
                .lock()
                .await
                .allowed_unused_rollbacks()
                .is_empty()
        );
        assert_eq!(std::fs::read(path).unwrap(), original);
        task.abort();
    })
    .await
    .unwrap();
}
