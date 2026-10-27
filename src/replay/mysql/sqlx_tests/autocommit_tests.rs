use super::*;

pub(super) fn cold_records() -> Vec<Value> {
    let connection = Uuid::new_v4();
    let mut records = vec![
        exchange(
            "SET AUTOCOMMIT = 0",
            json!({"status":"ok", "server_status":0, "affected_rows":0,"last_insert_id":0}),
        ),
        exchange(
            "SELECT id FROM users WHERE id=1",
            json!({"status":"resultset", "server_status":1,
            "columns":[{"name":"id","family":"integer","sql_type":"INT"}],
            "rows":[[{"kind":"integer","value":1}]]}),
        ),
        exchange(
            "ROLLBACK",
            json!({"status":"ok", "server_status":0, "affected_rows":0,"last_insert_id":0}),
        ),
        exchange(
            "ROLLBACK",
            json!({"status":"ok", "server_status":0, "affected_rows":0,"last_insert_id":0}),
        ),
    ];
    for (record, (seq, before)) in records.iter_mut().zip([(3, 2), (5, 0), (6, 1), (7, 0)]) {
        record["connection_id"] = json!(connection);
        record["query_sequence"] = json!(seq);
        record["server_status_before"] = json!(before);
    }
    records
}

#[tokio::test]
async fn cold_source_setup_can_be_omitted_or_consumed_by_normal_sqlx_clients() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for policy in [false, true] {
            for send_setup in [false, true] {
                let (temp, addr, runtime, task) = fixture(&cold_records(), policy).await;
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
                if send_setup {
                    // Prepared constant assignment also uses the ordinary
                    // matcher, including session-prefix spelling differences.
                    sqlx::query("SET @@session.autocommit=0")
                        .execute(&mut client)
                        .await
                        .unwrap();
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
                    assert_eq!(
                        state.allowed_unused_autocommit().len(),
                        usize::from(!send_setup)
                    );
                    assert_eq!(state.allowed_unused_rollbacks().len(), 2);
                    assert!(state.mysql.events.unmatched_queries.is_empty());
                    let report = serde_json::to_value(state.snapshot_report()).unwrap();
                    assert_eq!(
                        report["allowed_unused_mysql_autocommit_exchanges"]
                            .as_array()
                            .map(Vec::len)
                            .unwrap_or_default(),
                        usize::from(!send_setup)
                    );
                    assert_eq!(state.mysql.exchanges.len(), 4);
                }
                assert_eq!(std::fs::read(path).unwrap(), original);
                task.abort();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn autocommit_failures_and_multi_write_session_omissions_stay_visible() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut records = cold_records();
        records[1]["sql"] = json!("UPDATE users SET active=0 WHERE id=1");
        records[1]["response"] =
            json!({"status":"ok", "server_status":1,"affected_rows":1,"last_insert_id":0});
        let mut second_write = records[1].clone();
        second_write["sql"] = json!("UPDATE users SET active=0 WHERE id=2");
        second_write["query_sequence"] = json!(6);
        second_write["server_status_before"] = json!(1);
        records[2]["query_sequence"] = json!(7);
        records[3]["query_sequence"] = json!(8);
        records.insert(2, second_write);
        let (temp, addr, runtime, task) = fixture(&records, false).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        sqlx::raw_sql("UPDATE users SET active=0 WHERE id=1")
            .execute(&mut client)
            .await
            .unwrap();
        sqlx::raw_sql("UPDATE users SET active=0 WHERE id=2")
            .execute(&mut client)
            .await
            .unwrap();
        {
            let state = runtime.state.lock().await;
            assert!(state.allowed_unused_autocommit().is_empty());
            assert!(state.transaction_equivalent_autocommit().is_empty());
            assert!(state.mysql.case_is_dirty("case-id"));
            assert!(!state.mysql.events.unmatched_queries.is_empty());
            assert_eq!(
                state
                    .unused_exchanges(ReplaySource::Case)
                    .iter()
                    .map(|e| e.index)
                    .collect::<Vec<_>>(),
                vec![0, 3]
            );
        }
        task.abort();

        let records = [exchange(
            "SET AUTOCOMMIT=1",
            json!({"status":"error", "error_code":1205, "error_message":"recorded failure"}),
        )];
        let (temp, addr, runtime, task) = fixture(&records, true).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        let error = sqlx::raw_sql("SET AUTOCOMMIT=1")
            .execute(&mut client)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("recorded failure"));
        assert_eq!(
            runtime.state.lock().await.mysql.events.matched_query_count,
            1
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn recorded_ping_continuity_allows_multiple_normal_driver_read_sessions() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut records = cold_records();
        let mut ping = records[3].clone();
        ping["command"] = json!("COM_PING");
        ping["sql"] = Value::Null;
        ping["query_sequence"] = json!(8);
        records.push(ping);
        for (index, sequence, before) in [(1, 9, 0), (2, 10, 1), (3, 11, 0)] {
            let mut record = records[index].clone();
            record["query_sequence"] = json!(sequence);
            record["server_status_before"] = json!(before);
            records.push(record);
        }
        let (temp, addr, runtime, task) = fixture(&records, true).await;
        let capture = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
        let original = std::fs::read(&capture).unwrap();
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        for _ in 0..2 {
            client.ping().await.unwrap();
            let row = sqlx::query("SELECT id FROM users WHERE id=?")
                .bind(1_i32)
                .fetch_one(&mut client)
                .await
                .unwrap();
            assert_eq!(row.get::<i32, _>("id"), 1);
        }
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert_eq!(state.allowed_unused_autocommit().len(), 1);
        assert_eq!(state.allowed_unused_rollbacks().len(), 4);
        assert_eq!(
            state.mysql.exchanges.len(),
            7,
            "PING is proof, not a required business call"
        );
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert_eq!(std::fs::read(capture).unwrap(), original);
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn case_local_inactive_gaps_allow_cold_setup_omission_across_seven_read_sessions() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let base = cold_records();
        let mut records = vec![base[0].clone()];
        for index in 0..7 {
            for (offset, template) in base[1..].iter().enumerate() {
                let mut record = template.clone();
                record["query_sequence"] = json!(5 + 4 * index + offset);
                records.push(record);
            }
        }
        for policy in [false, true] {
            let (temp, addr, runtime, task) = fixture(&records, policy).await;
            let capture = temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
            let original = std::fs::read(&capture).unwrap();
            let mut client = connect(addr, &capture.parent().unwrap().join(".replay/ca.pem")).await;
            {
                let state = runtime.state.lock().await;
                assert_eq!(state.allowed_unused_autocommit().len(), 1);
                assert_eq!(state.unused_exchanges(ReplaySource::Case).len(), 7);
            }
            for _ in 0..7 {
                client.ping().await.unwrap();
                let row = sqlx::query("SELECT id FROM users WHERE id=?")
                    .bind(1_i32)
                    .fetch_one(&mut client)
                    .await
                    .unwrap();
                assert_eq!(row.get::<i32, _>("id"), 1);
            }
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.allowed_unused_autocommit().len(), 1);
            assert_eq!(state.allowed_unused_rollbacks().len(), 14);
            assert_eq!(state.mysql.exchanges.len(), 22);
            assert_eq!(state.mysql.events.matched_query_count, 7);
            assert!(state.mysql.events.unmatched_queries.is_empty());
            let report = serde_json::to_value(state.snapshot_report()).unwrap();
            assert_eq!(
                report["allowed_unused_mysql_autocommit_exchanges"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(std::fs::read(&capture).unwrap(), original);
            task.abort();
        }
    })
    .await
    .unwrap();
}
