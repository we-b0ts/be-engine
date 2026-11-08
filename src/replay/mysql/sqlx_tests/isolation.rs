//! Actual TLS/MySQL clients exercise scoped isolation without changing SQL data.
use super::super::isolation::tests::{
    baseline, connection_default_records, reasserted_records, record, records,
};
use super::*;
use sqlx::Executor;

async fn open(address: SocketAddr, temp: &tempfile::TempDir) -> MySqlConnection {
    connect(
        address,
        &temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
    )
    .await
}

async fn body(client: &mut MySqlConnection) {
    let mut transaction = client.begin().await.unwrap();
    let id: i32 = sqlx::query_scalar("SELECT id FROM items WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    assert_eq!(id, 1);
    sqlx::query("UPDATE items SET value=? WHERE id=?")
        .bind(2_i32)
        .bind(1_i32)
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

#[tokio::test]
async fn read_committed_default_can_be_omitted_without_a_transaction_reset() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut source = connection_default_records();
        let mut read = records().remove(2);
        read["query_sequence"] = json!(7);
        source.push(read);
        source.push(record(8, "ROLLBACK", 1, 0));
        let (temp, address, runtime, task) = fixture(&source, false).await;
        let mut client = open(address, &temp).await;
        client.execute("SET AUTOCOMMIT = 0").await.unwrap();
        let id: i32 = sqlx::query_scalar("SELECT id FROM items WHERE id=?")
            .bind(1_i32)
            .fetch_one(&mut client)
            .await
            .unwrap();
        assert_eq!(id, 1);
        client.execute("ROLLBACK").await.unwrap();

        let state = runtime.state.lock().await;
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert!(state.mysql.isolation.audit().is_empty());
        let report = serde_json::to_value(state.snapshot_report()).unwrap();
        let omitted = report["allowed_unused_mysql_connection_read_committed_exchanges"]
            .as_array()
            .unwrap();
        assert_eq!(omitted.len(), 1);
        assert_eq!(omitted[0]["query_sequence"], 5);
        assert_eq!(
            state.mysql.exchanges[omitted[0]["index"].as_u64().unwrap() as usize].status,
            ReplayExchangeStatus::Available
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_read_does_not_consume_a_future_isolation_transaction_member() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut source = records();
        let mut ordinary = source[2].clone();
        ordinary["connection_id"] = json!(Uuid::from_u128(92));
        ordinary["server_status_before"] = json!(2);
        ordinary["response"]["server_status"] = json!(2);
        ordinary["response"]["rows"] = json!([]);
        source.push(ordinary);

        let (temp, address, runtime, task) =
            fixture_with_global(&source, &[baseline()], None).await;
        let mut reader = open(address, &temp).await;
        let id: Option<i32> = sqlx::query_scalar("SELECT id FROM items WHERE id=?")
            .bind(1_i32)
            .fetch_optional(&mut reader)
            .await
            .unwrap();
        assert_eq!(id, None);

        let mut writer = open(address, &temp).await;
        writer
            .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .await
            .unwrap();
        body(&mut writer).await;

        let state = runtime.state.lock().await;
        assert!(state.mysql.events.unmatched_queries.is_empty());
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert_eq!(state.mysql.isolation.audit()[0]["phase"], "covered");
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn next_isolation_uses_real_transaction_delivery_and_omits_only_the_source_session_reset() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for (policy, pooled_source, same_baseline, reasserted) in [(None, false, false, false), (None, true, false, false),
            (Some("format: traffic-policy/v3\nmysql: {}\njson:\n  fields:\n    /id: {kind: identity, formats: [decimal]}\n"), false, false, false),
            (None, false, true, false), (None, true, true, false),
            (None, false, true, true), (None, true, true, true)] {
            let mut source = if reasserted { reasserted_records() } else { records() };
            let second = source.clone().into_iter().map(|mut row| {
                row["query_sequence"] = json!(row["query_sequence"].as_u64().unwrap() + 10);
                row
            }).collect::<Vec<_>>();
            source.extend(second);
            let mut probe = baseline();
            if same_baseline {
                probe["response"]["rows"][0][0]["value"] = json!("READ-COMMITTED");
                for row in &mut source {
                    if row["sql"] == "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ" {
                        row["sql"] = json!("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");
                    }
                }
            }
            if pooled_source {
                // Dialect initialization ran on another original pool socket;
                // sequence numbers are local to each socket, never comparable.
                probe["query_sequence"] = json!(70);
                for row in &mut source {
                    row["connection_id"] = json!(Uuid::from_u128(92));
                    row["timestamp"] = json!("2020-01-01T00:00:01Z");
                }
            }
            let (temp, address, runtime, task) = fixture_with_global(&source, &[probe], policy).await;
            let mut client = open(address, &temp).await;
            let default: String = sqlx::query_scalar("SELECT @@transaction_isolation")
                .fetch_one(&mut client).await.unwrap();
            assert_eq!(default, if same_baseline { "READ-COMMITTED" } else { "REPEATABLE-READ" });
            for _ in 0..2 {
                client.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED").await.unwrap();
                body(&mut client).await;
            }
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty(), "{:?}", state.unused_exchanges(ReplaySource::Case));
            assert!(state.mysql.events.unmatched_queries.is_empty(), "{:?}", state.mysql.events.unmatched_queries);
            let audit = state.mysql.isolation.audit();
            assert_eq!(audit.len(), 2);
            assert!(audit.iter().all(|v| v["reset_omission_proven"] == true));
            assert!(audit.iter().all(|v| v["source_reassertion_indices"].as_array().unwrap().len()
                == usize::from(reasserted)));
            assert_eq!(state.mysql.exchanges.iter().filter(|e|
                e.optional_session == Some(OptionalSessionExchange::TransactionIsolation)
                && e.status == ReplayExchangeStatus::Available).count(), if reasserted { 4 } else { 2 });
            task.abort();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn next_isolation_matches_the_earlier_transaction_with_a_savepoint() {
    let mut source = records();
    source.insert(3, record(11, "SAVEPOINT sa_savepoint_1", 1, 1));
    source.insert(5, record(13, "RELEASE SAVEPOINT sa_savepoint_1", 1, 1));
    for (offset, row) in source.iter_mut().enumerate() {
        row["query_sequence"] = json!(8 + offset);
    }
    let mut later = records();
    later[2]["sql"] = json!("SELECT id FROM items WHERE id=2");
    for (offset, row) in later.iter_mut().enumerate() {
        row["query_sequence"] = json!(17 + offset);
    }
    source.extend(later);
    let (temp, address, runtime, task) = fixture_with_global(&source, &[baseline()], None).await;
    let mut client = open(address, &temp).await;
    client
        .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .await
        .unwrap();
    let mut transaction = client.begin().await.unwrap();
    let id: i32 = sqlx::query_scalar("SELECT id FROM items WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    assert_eq!(id, 1);
    let mut nested = sqlx::Acquire::begin(&mut transaction).await.unwrap();
    sqlx::query("UPDATE items SET value=? WHERE id=?")
        .bind(2_i32)
        .bind(1_i32)
        .execute(&mut *nested)
        .await
        .unwrap();
    nested.commit().await.unwrap();
    transaction.commit().await.unwrap();
    let state = runtime.state.lock().await;
    assert!(state.mysql.events.unmatched_queries.is_empty());
    let audit = state.mysql.isolation.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["source_setup_sequence"], 8);
    assert_eq!(audit[0]["phase"], "covered");
    assert_eq!(audit[0]["required_members"], 5);
    task.abort();
}

#[tokio::test]
async fn isolation_rejects_unproven_modes_active_settings_cross_socket_and_missing_begin() {
    tokio::time::timeout(Duration::from_secs(40), async {
        for scenario in [
            "missing-baseline",
            "different-level",
            "active",
            "cross-socket",
            "missing-begin",
            "missing-member",
            "reasserted-missing-member",
            "ambiguous-default",
        ] {
            let globals = if scenario == "ambiguous-default" {
                let mut another = baseline();
                another["connection_id"] = json!(Uuid::from_u128(93));
                another["response"]["rows"][0][0]["value"] = json!("READ-COMMITTED");
                vec![baseline(), another]
            } else if scenario == "reasserted-missing-member" {
                let mut probe = baseline();
                probe["response"]["rows"][0][0]["value"] = json!("READ-COMMITTED");
                vec![probe]
            } else if scenario == "missing-baseline" {
                vec![]
            } else {
                vec![baseline()]
            };
            let rows = if scenario == "reasserted-missing-member" {
                reasserted_records()
            } else {
                records()
            };
            let (temp, address, runtime, task) = fixture_with_global(&rows, &globals, None).await;
            let mut client = open(address, &temp).await;
            match scenario {
                "active" => {
                    let mut transaction = client.begin().await.unwrap();
                    assert!(
                        transaction
                            .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                            .await
                            .is_err()
                    );
                    assert!(
                        transaction
                            .rollback()
                            .await
                            .unwrap_err()
                            .as_database_error()
                            .is_none()
                    );
                }
                "different-level" => {
                    assert!(
                        client
                            .execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                            .await
                            .is_err()
                    );
                }
                "missing-baseline" | "ambiguous-default" => {
                    assert!(
                        client
                            .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                            .await
                            .is_err()
                    );
                }
                "cross-socket" => {
                    client
                        .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        .await
                        .unwrap();
                    let mut other = open(address, &temp).await;
                    let mut transaction = other.begin().await.unwrap();
                    assert!(
                        sqlx::query("SELECT id FROM items WHERE id=?")
                            .bind(1_i32)
                            .fetch_one(&mut *transaction)
                            .await
                            .is_err()
                    );
                    assert!(
                        transaction
                            .rollback()
                            .await
                            .unwrap_err()
                            .as_database_error()
                            .is_none()
                    );
                }
                "missing-begin" => {
                    client
                        .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        .await
                        .unwrap();
                    assert!(
                        sqlx::query("SELECT id FROM items WHERE id=?")
                            .bind(1_i32)
                            .fetch_one(&mut client)
                            .await
                            .is_err()
                    );
                }
                "missing-member" | "reasserted-missing-member" => {
                    client
                        .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        .await
                        .unwrap();
                    let mut transaction = client.begin().await.unwrap();
                    sqlx::query("UPDATE items SET value=? WHERE id=?")
                        .bind(2_i32)
                        .bind(1_i32)
                        .execute(&mut *transaction)
                        .await
                        .unwrap();
                    let _ = transaction.commit().await;
                }
                _ => unreachable!(),
            }
            let state = runtime.state.lock().await;
            assert!(
                !state
                    .mysql
                    .isolation
                    .audit()
                    .iter()
                    .any(|v| v["reset_omission_proven"] == true),
                "{scenario}"
            );
            assert!(
                !state.unused_exchanges(ReplaySource::Case).is_empty(),
                "{scenario}"
            );
            task.abort();
        }
    })
    .await
    .unwrap();
}
