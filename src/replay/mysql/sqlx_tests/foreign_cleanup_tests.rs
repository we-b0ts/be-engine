use super::*;

fn control(sequence: u64, sql: &str, before: u16, after: u16) -> Value {
    let mut record = exchange(
        sql,
        json!({"status":"ok", "server_status":after,
        "affected_rows":0, "last_insert_id":0}),
    );
    record["connection_id"] = json!(Uuid::nil());
    record["query_sequence"] = json!(sequence);
    record["server_status_before"] = json!(before);
    record
}

fn read(sequence: u64, before: u16, id: i32) -> Value {
    let mut record = control(
        sequence,
        &format!("SELECT id FROM users WHERE id={id}"),
        before,
        1,
    );
    record["response"] = json!({"status":"resultset", "server_status":1,
        "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
        "rows":[[{"kind":"integer","value":id}]]});
    record
}

#[tokio::test]
async fn foreign_rollback_can_be_omitted_while_current_business_rollback_stays_required() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for (correct_end, consume_foreign_first) in
            [(true, false), (false, false), (true, true), (false, true)]
        {
            let mut write = control(19369, "UPDATE users SET active=0 WHERE id=1", 1, 1);
            write["response"]["affected_rows"] = json!(1);
            let records = [
                control(19366, "ROLLBACK", 1, 0),
                control(19367, "ROLLBACK", 0, 0),
                control(19368, "BEGIN", 0, 1),
                write,
                control(19370, "ROLLBACK", 1, 0),
            ];
            let global = [read(19364, 0, 1), read(19365, 1, 1)];
            let (temp, addr, runtime, task) = fixture_with_global(&records, &global, None).await;
            let original = std::fs::read(temp.path().join("case-id/dependencies.jsonl")).unwrap();
            let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
            if consume_foreign_first {
                for _ in 0..2 {
                    sqlx::raw_sql("ROLLBACK")
                        .execute(&mut client)
                        .await
                        .unwrap();
                }
            }
            let mut tx = client.begin().await.unwrap();
            sqlx::query("UPDATE users SET active=0 WHERE id=1")
                .execute(&mut *tx)
                .await
                .unwrap();
            if correct_end {
                tx.rollback().await.unwrap();
            } else {
                tx.commit().await.unwrap();
            }
            let state = runtime.state.lock().await;
            assert_eq!(state.mysql.case_is_dirty("case-id"), !correct_end);
            assert_eq!(
                state.unused_exchanges(ReplaySource::Case).len(),
                usize::from(!correct_end)
            );
            assert_eq!(
                state.allowed_unused_rollbacks().len(),
                if consume_foreign_first { 0 } else { 2 }
            );
            assert_eq!(
                state.unused_exchanges(ReplaySource::Global).len(),
                2,
                "global reads are still evidence"
            );
            assert_eq!(
                std::fs::read(temp.path().join("case-id/dependencies.jsonl")).unwrap(),
                original
            );
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn business_commit_takes_precedence_only_after_its_recorded_prefix_is_consumed() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for consume_foreign_first in [false, true] {
            let mut write = control(104, "UPDATE users SET active=0 WHERE id=1", 1, 1);
            write["response"]["affected_rows"] = json!(1);
            let records = [
                control(102, "COMMIT", 1, 0),
                control(103, "BEGIN", 0, 1),
                write,
                control(105, "COMMIT", 1, 0),
            ];
            let (temp, addr, runtime, task) =
                fixture_with_global(&records, &[read(100, 0, 1), read(101, 1, 1)], None).await;
            let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
            if consume_foreign_first {
                sqlx::raw_sql("COMMIT").execute(&mut client).await.unwrap();
                let state = runtime.state.lock().await;
                assert!(
                    state.mysql.exchanges[2].status.is_consumed(),
                    "startup cleanup consumes the foreign end"
                );
                assert!(
                    !state.mysql.exchanges[5].status.is_consumed(),
                    "the business end remains required"
                );
            }
            let mut tx = client.begin().await.unwrap();
            sqlx::query("UPDATE users SET active=0 WHERE id=1")
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let state = runtime.state.lock().await;
            assert!(!state.mysql.case_is_dirty("case-id"));
            assert_eq!(
                state.allowed_unused_commits().len(),
                usize::from(!consume_foreign_first)
            );
            assert!(state.mysql.exchanges[5].status.is_consumed());
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn global_read_commit_is_optional_and_still_finitely_consumed_by_real_driver() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let records = [control(102, "COMMIT", 1, 0), read(103, 0, 2)];
        let global = [read(100, 0, 1), read(101, 1, 1)];
        let (temp, addr, runtime, task) = fixture_with_global(&records, &global, None).await;
        let mut client = connect(addr, &temp.path().join("case-id/.replay/ca.pem")).await;
        let row = sqlx::query("SELECT id FROM users WHERE id=2")
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(row.get::<i32, _>("id"), 2);
        {
            let state = runtime.state.lock().await;
            assert!(!state.mysql.case_is_dirty("case-id"));
            let report = serde_json::to_value(state.snapshot_report()).unwrap();
            assert_eq!(
                report["allowed_unused_mysql_commit_exchanges"][0]["query_sequence"],
                102
            );
            assert_eq!(state.allowed_unused_commits().len(), 1);
        }
        sqlx::raw_sql("COMMIT").execute(&mut client).await.unwrap();
        sqlx::raw_sql("COMMIT").execute(&mut client).await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.allowed_unused_commits().is_empty());
        assert_eq!(
            state
                .mysql
                .exchanges
                .iter()
                .filter(|e| e.source == ReplaySource::Case && e.status.is_consumed())
                .count(),
            2
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn optional_commit_delivery_failure_still_marks_case_dirty() {
    let records = [read(100, 0, 1), control(101, "COMMIT", 1, 0)];
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
    state.complete_exchange(&read);
    let commit = state
        .match_exchange(&identity, "COM_QUERY", Some("COMMIT"), None)
        .unwrap();
    assert!(!state.mysql.case_is_dirty("case-id"));
    assert_eq!(state.allowed_unused_commits().len(), 1);
    assert_eq!(state.mysql.events.matched_query_count, 1);
    state.fail_exchange(&commit, &identity, "test delivery failure");
    assert!(state.mysql.case_is_dirty("case-id"));
    assert!(state.allowed_unused_commits().is_empty());
    assert_eq!(state.unused_exchanges(ReplaySource::Case).len(), 1);
    task.abort();
}
