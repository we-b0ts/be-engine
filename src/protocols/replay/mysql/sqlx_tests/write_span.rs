//! Real SQLx coverage of lazy write transactions, including pooled sockets.
use super::*;

fn source(writes: usize, end: &str, setup: bool) -> Vec<Value> {
    let connection = Uuid::from_u128(77);
    let mut values = Vec::new();
    let mut sequence = 1;
    let mut push = |sql: String, before: u16, after: u16, read: Option<i32>| {
        let mut record = exchange(
            &sql,
            json!({"status":"ok", "server_status":after,
            "affected_rows":0, "last_insert_id":0}),
        );
        record["connection_id"] = json!(connection);
        record["query_sequence"] = json!(sequence);
        record["server_status_before"] = json!(before);
        if let Some(id) = read {
            record["response"] = json!({"status":"resultset", "server_status":after,
                "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":id}]]});
        }
        sequence += 1;
        values.push(record);
    };
    if setup {
        push("SET AUTOCOMMIT=0".into(), 2, 0, None);
    }
    push("SELECT id FROM items WHERE id=100".into(), 0, 1, Some(100));
    for write in 1..=writes {
        push(
            format!("UPDATE items SET value={write} WHERE id=1"),
            1,
            1,
            None,
        );
    }
    push("SELECT id FROM items WHERE id=103".into(), 1, 1, Some(103));
    push(end.into(), 1, 0, None);
    values
}

async fn read(client: &mut MySqlConnection, id: i32) {
    assert_eq!(
        sqlx::query("SELECT id FROM items WHERE id=?")
            .bind(id)
            .fetch_one(client)
            .await
            .unwrap()
            .get::<i32, _>(0),
        id
    );
}

async fn write(client: &mut MySqlConnection, value: i32) {
    sqlx::query("UPDATE items SET value=? WHERE id=1")
        .bind(value)
        .execute(client)
        .await
        .unwrap();
}

fn ca(temp: &tempfile::TempDir) -> std::path::PathBuf {
    temp.path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")
}

#[tokio::test]
async fn single_write_autocommit_omits_commit_and_keeps_witness_flags_on_its_socket() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for setup in [false, true] {
            let (temp, address, runtime, task) = fixture(&source(1, "COMMIT", setup), false).await;
            let mut reader = connect(address, &ca(&temp)).await;
            let mut writer = connect(address, &ca(&temp)).await;
            read(&mut reader, 100).await;
            write(&mut writer, 1).await;
            let mut read_tx = reader.begin().await.unwrap();
            read(&mut read_tx, 103).await;
            let state = runtime.state.lock().await;
            let end = state
                .protocols
                .mysql
                .exchanges
                .iter()
                .position(|e| e.record.sql.as_deref() == Some("COMMIT"))
                .unwrap();
            let proof = state
                .protocols
                .mysql
                .transaction_equivalence
                .diagnostic(end)
                .unwrap();
            assert_eq!(proof["reason"], "target_autocommit_single_write");
            assert_eq!(proof["source_transactions"][0]["target_status_before"], 2);
            assert_eq!(proof["source_transactions"][0]["target_status_after"], 2);
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert!(!state.snapshot_report().is_dirty());
            drop(state);
            read_tx.commit().await.unwrap();
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn write_spans_allow_prefix_reads_on_another_socket_and_require_trailing_reads() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for end in ["COMMIT", "ROLLBACK"] {
            for setup in [false, true] {
                let (temp, address, runtime, task) = fixture(&source(2, end, setup), false).await;
                let mut reader = connect(address, &ca(&temp)).await;
                let mut writer = connect(address, &ca(&temp)).await;
                read(&mut reader, 100).await;
                let mut tx = writer.begin().await.unwrap();
                write(&mut tx, 1).await;
                write(&mut tx, 2).await;
                read(&mut tx, 103).await;
                if end == "COMMIT" {
                    tx.commit().await.unwrap();
                } else {
                    tx.rollback().await.unwrap();
                }
                let state = runtime.state.lock().await;
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                assert!(
                    !state.snapshot_report().is_dirty(),
                    "{end}: {:?}",
                    state.protocols.mysql.events.unmatched_queries
                );
                task.abort();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn transaction_ending_before_a_trailing_read_is_dirty_without_a_source_setup() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (temp, address, runtime, task) = fixture(&source(2, "COMMIT", false), false).await;
        let mut reader = connect(address, &ca(&temp)).await;
        let mut writer = connect(address, &ca(&temp)).await;
        read(&mut reader, 100).await;
        let mut tx = writer.begin().await.unwrap();
        write(&mut tx, 1).await;
        write(&mut tx, 2).await;
        tx.commit().await.unwrap();
        assert!(
            sqlx::query("SELECT id FROM items WHERE id=?")
                .bind(103_i32)
                .fetch_one(&mut reader)
                .await
                .is_err()
        );
        let state = runtime.state.lock().await;
        assert!(state.snapshot_report().is_dirty());
        let failure = state
            .protocols
            .mysql
            .events
            .unmatched_queries
            .iter()
            .find(|q| q.diagnostic.is_some())
            .unwrap();
        assert_eq!(
            failure.diagnostic.as_ref().unwrap()["reason"],
            "target_transaction_members_or_end_differ"
        );
        assert_eq!(
            failure.diagnostic.as_ref().unwrap()["source_transactions"][0]["write_count"],
            2
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_single_write_rollback_cannot_be_replaced_by_autocommit() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = source(1, "ROLLBACK", false);
        values[1]["response"]["affected_rows"] = json!(1);
        let (temp, address, runtime, task) = fixture(&values, false).await;
        let mut client = connect(address, &ca(&temp)).await;
        read(&mut client, 100).await;
        assert!(
            sqlx::query("UPDATE items SET value=? WHERE id=1")
                .bind(1_i32)
                .execute(&mut client)
                .await
                .is_err()
        );
        let state = runtime.state.lock().await;
        assert!(state.snapshot_report().is_dirty());
        assert!(state.allowed_unused_rollbacks().is_empty());
        assert_eq!(state.protocols.mysql.events.matched_query_count, 1);
        let failure = state
            .protocols
            .mysql
            .events
            .unmatched_queries
            .iter()
            .find(|q| q.diagnostic.is_some())
            .unwrap();
        assert_eq!(
            failure.diagnostic.as_ref().unwrap()["reason"],
            "target_transaction_missing"
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn idle_and_empty_transaction_cleanup_cannot_consume_a_business_end() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (temp, address, runtime, task) = fixture(&source(2, "COMMIT", false), false).await;
        let mut client = connect(address, &ca(&temp)).await;
        for sql in ["COMMIT", "ROLLBACK", "BEGIN", "COMMIT"] {
            sqlx::raw_sql(sql).execute(&mut client).await.unwrap();
        }
        read(&mut client, 100).await;
        let mut tx = client.begin().await.unwrap();
        write(&mut tx, 1).await;
        write(&mut tx, 2).await;
        read(&mut tx, 103).await;
        tx.commit().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert!(!state.snapshot_report().is_dirty());
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_source_begin_retains_its_complete_transaction() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = source(2, "COMMIT", true);
        values[0]["sql"] = json!("BEGIN");
        values[0]["response"]["server_status"] = json!(3);
        for value in &mut values[1..] {
            value["server_status_before"] = json!(3);
            value["response"]["server_status"] = json!(3);
        }
        values.last_mut().unwrap()["response"]["server_status"] = json!(2);
        let (temp, address, runtime, task) = fixture(&values, false).await;
        let mut client = connect(address, &ca(&temp)).await;
        let mut tx = client.begin().await.unwrap();
        read(&mut tx, 100).await;
        write(&mut tx, 1).await;
        write(&mut tx, 2).await;
        read(&mut tx, 103).await;
        tx.commit().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert!(!state.snapshot_report().is_dirty());
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn locking_reads_keep_a_strict_transaction_instead_of_disabling_proof() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = source(2, "COMMIT", false);
        values[0]["sql"] = json!("SELECT id FROM items WHERE id=100 FOR UPDATE");
        let (temp, address, runtime, task) = fixture(&values, false).await;
        let mut client = connect(address, &ca(&temp)).await;
        let mut tx = client.begin().await.unwrap();
        assert_eq!(
            sqlx::query("SELECT id FROM items WHERE id=100 FOR UPDATE")
                .fetch_one(&mut *tx)
                .await
                .unwrap()
                .get::<i32, _>(0),
            100
        );
        write(&mut tx, 1).await;
        write(&mut tx, 2).await;
        read(&mut tx, 103).await;
        tx.commit().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert!(!state.snapshot_report().is_dirty());
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn only_observed_zero_row_or_failed_single_update_can_omit_rollback() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for failed in [false, true] {
            for active_after_error in [false, true] {
                let mut values = source(1, "ROLLBACK", false);
                values.remove(2);
                values[2]["query_sequence"] = json!(3);
                if failed {
                    values.remove(0);
                    values[0]["query_sequence"] = json!(1);
                    values[0]["server_status_before"] = json!(0);
                    values[0]["response"] = json!({"status":"error","error_code":1205,
                        "error_message":"recorded update failure"});
                    values[1]["query_sequence"] = json!(2);
                    values[1]["server_status_before"] = json!(u16::from(active_after_error));
                }
                let (temp, address, runtime, task) = fixture(&values, false).await;
                let mut client = connect(address, &ca(&temp)).await;
                if !failed {
                    read(&mut client, 100).await;
                }
                let result = sqlx::query("UPDATE items SET value=1 WHERE id=1")
                    .execute(&mut client)
                    .await;
                if failed {
                    let error = result.unwrap_err();
                    assert_eq!(
                        error
                            .as_database_error()
                            .unwrap()
                            .downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                            .number(),
                        1205
                    );
                } else {
                    assert_eq!(result.unwrap().rows_affected(), 0);
                }
                let state = runtime.state.lock().await;
                assert!(
                    state.unused_exchanges(ReplaySource::Case).is_empty(),
                    "{:?}",
                    state.unused_exchanges(ReplaySource::Case)
                );
                assert!(
                    !state.snapshot_report().is_dirty(),
                    "{:?}",
                    state.protocols.mysql.events.unmatched_queries
                );
                let end = state
                    .protocols
                    .mysql
                    .exchanges
                    .iter()
                    .position(|e| e.record.sql.as_deref() == Some("ROLLBACK"))
                    .unwrap();
                let proof = state
                    .protocols
                    .mysql
                    .transaction_equivalence
                    .diagnostic(end)
                    .unwrap();
                let interval = &proof["source_transactions"][0];
                assert_eq!(interval["write_count"], 1);
                assert_eq!(
                    interval["single_update_outcome"],
                    if failed {
                        "error"
                    } else {
                        "zero_affected_rows"
                    }
                );
                assert_eq!(interval["autocommit_eligible"], true);
                task.abort();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_failed_update_still_works_inside_an_explicit_target_rollback() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = source(1, "ROLLBACK", false);
        values[1]["response"] = json!({"status":"error","error_code":1205,
            "error_message":"recorded update failure"});
        let (temp, address, runtime, task) = fixture(&values, false).await;
        let mut client = connect(address, &ca(&temp)).await;
        read(&mut client, 100).await;
        let mut tx = client.begin().await.unwrap();
        assert!(
            sqlx::query("UPDATE items SET value=1 WHERE id=1")
                .execute(&mut *tx)
                .await
                .is_err()
        );
        read(&mut tx, 103).await;
        tx.rollback().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert!(
            !state.snapshot_report().is_dirty(),
            "{:?}",
            state.protocols.mysql.events.unmatched_queries
        );
        task.abort();
    })
    .await
    .unwrap();
}
