use super::*;

fn control(connection: Uuid, sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut record = exchange(
        sql,
        json!({"status":"ok", "server_status":after, "affected_rows":0, "last_insert_id":0}),
    );
    record["connection_id"] = json!(connection);
    record["query_sequence"] = json!(sequence);
    record["server_status_before"] = json!(before);
    record
}

fn read(connection: Uuid, sequence: u64, flags: u16) -> Value {
    let mut record = control(
        connection,
        sequence,
        "SELECT id FROM users WHERE id=7",
        flags,
        flags,
    );
    record["response"] = json!({"status":"resultset", "server_status":flags,
        "columns":[{"name":"id", "family":"integer", "sql_type":"INT"}],
        "rows":[[{"kind":"integer", "value":7}]]});
    record
}

#[tokio::test]
async fn explicit_read_transaction_does_not_require_orm_commit_or_rollback() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for end in ["COMMIT", "ROLLBACK"] {
            let connection = Uuid::new_v4();
            let records = [
                control(connection, 10, "BEGIN", 2, 3),
                read(connection, 11, 3),
                control(connection, 12, end, 3, 2),
            ];
            let (temp, addr, runtime, task) = fixture(&records, false).await;
            let path = temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
            let original = std::fs::read(&path).unwrap();
            let mut client = connect(
                addr,
                &temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
            )
            .await;
            sqlx::raw_sql("BEGIN").execute(&mut client).await.unwrap();
            assert_eq!(
                sqlx::query("SELECT id FROM users WHERE id=7")
                    .fetch_one(&mut client)
                    .await
                    .unwrap()
                    .get::<i32, _>("id"),
                7
            );
            client.close().await.unwrap();
            let state = runtime.state.lock().await;
            assert!(!state.mysql.case_is_dirty("case-id"), "{end}");
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.mysql.events.matched_query_count, 2);
            assert_eq!(
                state.allowed_unused_commits().len(),
                usize::from(end == "COMMIT")
            );
            assert_eq!(
                state.allowed_unused_rollbacks().len(),
                usize::from(end == "ROLLBACK")
            );
            assert_eq!(std::fs::read(path).unwrap(), original);
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn empty_source_ends_can_be_omitted_and_keep_finite_consumption_when_sent() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let connection = Uuid::new_v4();
        let records = [
            control(connection, 10, "COMMIT", 2, 2),
            control(connection, 11, "ROLLBACK", 2, 2),
            control(connection, 12, "COMMIT", 2, 2),
            read(connection, 13, 2),
        ];
        let (temp, addr, runtime, task) = fixture(&records, false).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        sqlx::query("SELECT id FROM users WHERE id=7")
            .fetch_one(&mut client)
            .await
            .unwrap();
        {
            let state = runtime.state.lock().await;
            assert!(!state.mysql.case_is_dirty("case-id"));
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.allowed_unused_commits().len(), 2);
            assert_eq!(state.allowed_unused_rollbacks().len(), 1);
            assert_eq!(state.mysql.events.matched_query_count, 1);
        }
        for sql in ["COMMIT", "COMMIT", "COMMIT", "ROLLBACK", "ROLLBACK"] {
            sqlx::raw_sql(sql).execute(&mut client).await.unwrap();
        }
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 4);
        assert!(state.allowed_unused_commits().is_empty());
        assert!(state.allowed_unused_rollbacks().is_empty());
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert!(!state.mysql.case_is_dirty("case-id"));
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn empty_cleanup_cannot_replace_a_write_transactions_required_end() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for end in ["COMMIT", "ROLLBACK"] {
            let connection = Uuid::new_v4();
            let mut write = control(connection, 11, "UPDATE users SET active=0 WHERE id=7", 3, 3);
            write["response"]["affected_rows"] = json!(1);
            let records = [
                control(connection, 10, "BEGIN", 2, 3),
                write,
                control(connection, 12, end, 3, 2),
                control(connection, 13, "COMMIT", 2, 2),
            ];
            let (temp, addr, runtime, task) = fixture(&records, false).await;
            let mut client = connect(
                addr,
                &temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
            )
            .await;
            sqlx::raw_sql("BEGIN").execute(&mut client).await.unwrap();
            assert_eq!(
                sqlx::query("UPDATE users SET active=0 WHERE id=7")
                    .execute(&mut client)
                    .await
                    .unwrap()
                    .rows_affected(),
                1
            );
            client.close().await.unwrap();
            let state = runtime.state.lock().await;
            assert!(state.mysql.case_is_dirty("case-id"), "{end}");
            let unused = state.unused_exchanges(ReplaySource::Case);
            assert_eq!(unused.len(), 1);
            assert_eq!(unused[0].index, 2);
            assert_eq!(state.allowed_unused_commits()[0].index, 3);
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_noop_end_delivery_stays_dirty_after_other_successful_cleanup() {
    for sql in ["COMMIT", "ROLLBACK"] {
        let connection = Uuid::new_v4();
        let records = [
            control(connection, 10, sql, 2, 2),
            control(connection, 11, sql, 2, 2),
        ];
        let (_temp, _addr, runtime, task) = fixture(&records, false).await;
        let mut state = runtime.state.lock().await;
        let source = &state.mysql.exchanges[0].identity;
        let identity = ReplaySessionIdentity {
            target: Some(source.target.clone()),
            database: source.database.clone(),
            username: source.username.clone(),
        };
        let first = state
            .match_exchange(&identity, "COM_QUERY", Some(sql), None)
            .unwrap();
        assert!(!state.mysql.case_is_dirty("case-id"));
        state.fail_exchange(&first, &identity, "test cleanup delivery failure");
        assert!(state.mysql.case_is_dirty("case-id"));
        let second = state
            .match_exchange(&identity, "COM_QUERY", Some(sql), None)
            .unwrap();
        assert!(second.claim.publish_wire());
        assert!(state.complete_exchange(&second));
        assert!(state.mysql.case_is_dirty("case-id"));
        let unused = state.unused_exchanges(ReplaySource::Case);
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].index, first.index);
        assert_eq!(state.mysql.events.unmatched_queries.len(), 1);
        assert!(
            state
                .match_exchange(&identity, "COM_QUERY", Some(sql), None)
                .is_none()
        );
        task.abort();
    }
}
