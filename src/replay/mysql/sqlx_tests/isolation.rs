//! Actual TLS/MySQL clients exercise scoped isolation without changing SQL data.
use super::super::isolation::tests::{baseline, records};
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
async fn next_isolation_uses_real_transaction_delivery_and_omits_only_the_source_session_reset() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for (policy, pooled_source) in [(None, false), (None, true),
            (Some("format: traffic-policy/v2\nmysql: {}\njson:\n  fields:\n    /id: {kind: identity, formats: [decimal]}\n"), false)] {
            let mut source = records();
            let second = records().into_iter().map(|mut row| {
                row["query_sequence"] = json!(row["query_sequence"].as_u64().unwrap() + 10);
                row
            }).collect::<Vec<_>>();
            source.extend(second);
            let mut probe = baseline();
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
            assert_eq!(default, "REPEATABLE-READ");
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
            assert_eq!(state.mysql.exchanges.iter().filter(|e|
                e.optional_session == Some(OptionalSessionExchange::TransactionIsolation)
                && e.status == ReplayExchangeStatus::Available).count(), 2);
            task.abort();
        }
    }).await.unwrap();
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
            "ambiguous-default",
        ] {
            let globals = if scenario == "ambiguous-default" {
                let mut another = baseline();
                another["connection_id"] = json!(Uuid::from_u128(93));
                another["response"]["rows"][0][0]["value"] = json!("READ-COMMITTED");
                vec![baseline(), another]
            } else if scenario == "missing-baseline" {
                vec![]
            } else {
                vec![baseline()]
            };
            let (temp, address, runtime, task) =
                fixture_with_global(&records(), &globals, None).await;
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
                    transaction.rollback().await.unwrap();
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
                    transaction.rollback().await.unwrap();
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
                "missing-member" => {
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
