use super::*;

#[tokio::test]
async fn matched_ranked_union_read_allows_cleanup_only_with_proven_pure_children() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for pure in [true, false] {
            let value = if pure { "id" } else { "custom_function()" };
            let sql = format!("SELECT ranked.id FROM (
                SELECT combined.id, row_number() OVER (PARTITION BY combined.id ORDER BY combined.id) AS rn
                FROM (SELECT {value} AS id FROM users UNION ALL
                    SELECT u.id FROM users u JOIN members m ON u.id=m.id
                    WHERE EXISTS (SELECT id FROM kinds WHERE id=u.id)) combined
                ) ranked WHERE ranked.rn=1");
            let mut records = transaction_records();
            records.remove(1);
            records[0]["sql"] = json!(sql);
            records[0]["server_status_before"] = json!(0);
            records[0]["response"] = json!({"status":"resultset", "server_status":33,
                "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":7}]]});
            for (index, record) in records.iter_mut().enumerate() {
                record["query_sequence"] = json!(100 + index);
                if index > 0 {
                    record["server_status_before"] = json!(if index == 1 { 33 } else { 0 });
                }
            }
            let (temp, addr, runtime, task) = fixture(&records, false).await;
            let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
            assert_eq!(sqlx::query(&sql).fetch_one(&mut client).await.unwrap().get::<i32,_>("id"),7);
            client.close().await.unwrap();
            let state = runtime.state.lock().await;
            assert_eq!(state.mysql.events.matched_query_count, 1);
            assert_eq!(state.allowed_unused_rollbacks().len(), if pure { 2 } else { 1 });
            assert_eq!(state.unused_exchanges(ReplaySource::Case).len(), usize::from(!pure),
                "matching a query does not prove unknown functions have no effects");
            task.abort();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn optional_rollback_stays_optional_during_delivery_but_failures_stay_dirty() {
    let mut records = transaction_records();
    records[0]["sql"] = json!("SELECT DISTINCT id FROM users WHERE id=1 OR id=2");
    records[0]["server_status_before"] = json!(0);
    records[0]["response"] = json!({"status":"resultset", "server_status":1,
        "columns":[{"name":"id","family":"integer","sql_type":"INT"}], "rows":[]});
    records.remove(1);
    for (i, record) in records.iter_mut().enumerate() {
        record["query_sequence"] = json!(2109 + i);
        if i > 0 {
            record["server_status_before"] = json!(if i == 1 { 1 } else { 0 });
        }
    }
    let (_temp, _addr, runtime, task) = fixture(&records, false).await;
    let mut state = runtime.state.lock().await;
    let source = &state.mysql.exchanges[0].identity;
    let identity = ReplaySessionIdentity {
        target: Some(source.target.clone()),
        database: source.database.clone(),
        username: source.username.clone(),
    };
    let read = state
        .match_exchange(&identity, "COM_QUERY", records[0]["sql"].as_str(), None)
        .unwrap();
    assert_eq!(
        state.mysql.exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    assert_eq!(
        state.unused_exchanges(ReplaySource::Case).len(),
        1,
        "in-flight business response is still required"
    );
    state.complete_exchange(&read);
    let rollback = state
        .match_exchange(&identity, "COM_QUERY", Some("ROLLBACK"), None)
        .unwrap();
    assert_eq!(
        state.mysql.exchanges[rollback.index].status,
        ReplayExchangeStatus::Responding
    );
    assert!(
        state.unused_exchanges(ReplaySource::Case).is_empty(),
        "snapshot during cleanup delivery must remain clean"
    );
    assert_eq!(state.allowed_unused_rollbacks().len(), 2);
    assert_eq!(
        state.mysql.events.matched_query_count, 1,
        "in-flight cleanup is not a completed call"
    );
    state.fail_exchange(&rollback, &identity, "test delivery failure");
    assert_eq!(
        state.unused_exchanges(ReplaySource::Case)[0].index,
        rollback.index
    );
    assert_eq!(state.allowed_unused_rollbacks().len(), 1);
    assert_eq!(state.mysql.events.unmatched_queries.len(), 1);
    let last = state
        .match_exchange(&identity, "COM_QUERY", Some("ROLLBACK"), None)
        .unwrap();
    state.complete_exchange(&last);
    assert!(state.allowed_unused_rollbacks().is_empty());
    assert_eq!(
        state.unused_exchanges(ReplaySource::Case).len(),
        1,
        "failure must survive other successful cleanup"
    );
    task.abort();
}

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
