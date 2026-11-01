//! A completed read-only transaction may end with COMMIT or ROLLBACK.
use super::super::isolation::tests::{baseline, record, records};
use super::*;
use sqlx::Executor;

fn source(end: &str) -> Vec<Value> {
    let mut rows = records();
    let mut second = rows[2].clone();
    second["query_sequence"] = json!(11);
    second["server_status_before"] = json!(1);
    second["sql"] = json!("SELECT id FROM items WHERE id=2");
    second["response"]["rows"][0][0]["value"] = json!(2);
    rows[3] = second;
    rows[4] = record(12, end, 1, 0);
    rows
}

async fn client(address: SocketAddr, temp: &tempfile::TempDir) -> MySqlConnection {
    connect(
        address,
        &temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
    )
    .await
}

#[tokio::test]
async fn read_only_isolation_reset_requires_all_reads_and_a_real_transaction_end() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for source_end in ["COMMIT", "ROLLBACK"] {
            for target_commit in [true, false] {
                let (temp, address, runtime, task) =
                    fixture_with_global(&source(source_end), &[baseline()], None).await;
                let mut client = client(address, &temp).await;
                client
                    .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    .await
                    .unwrap();
                let mut transaction = client.begin().await.unwrap();
                for id in [1_i32, 2] {
                    let actual: i32 = sqlx::query_scalar("SELECT id FROM items WHERE id=?")
                        .bind(id)
                        .fetch_one(&mut *transaction)
                        .await
                        .unwrap();
                    assert_eq!(actual, id);
                    let state = runtime.state.lock().await;
                    assert!(
                        !state.mysql.isolation.audit()[0]["reset_omission_proven"]
                            .as_bool()
                            .unwrap()
                    );
                }
                if target_commit {
                    transaction.commit().await.unwrap();
                } else {
                    transaction.rollback().await.unwrap();
                }
                let state = runtime.state.lock().await;
                let audit = state.mysql.isolation.audit();
                assert_eq!(
                    audit[0]["reset_omission_proven"], true,
                    "{source_end}, {target_commit}: {audit:?}"
                );
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                assert!(state.mysql.events.unmatched_queries.is_empty());
                task.abort();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn read_only_end_cannot_cover_a_missing_read_or_a_state_changing_source_transaction() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for scenario in ["missing-read", "write", "locking-read"] {
            let mut rows = source("ROLLBACK");
            if scenario == "write" {
                rows[3] = records()[3].clone();
            } else if scenario == "locking-read" {
                rows[3]["sql"] = json!("SELECT id FROM items WHERE id=2 FOR UPDATE");
            }
            let (temp, address, runtime, task) =
                fixture_with_global(&rows, &[baseline()], None).await;
            let mut client = client(address, &temp).await;
            client
                .execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .await
                .unwrap();
            let mut transaction = client.begin().await.unwrap();
            sqlx::query("SELECT id FROM items WHERE id=?")
                .bind(1_i32)
                .fetch_one(&mut *transaction)
                .await
                .unwrap();
            if scenario == "write" {
                transaction
                    .execute("UPDATE items SET value=2 WHERE id=1")
                    .await
                    .unwrap();
            } else if scenario == "locking-read" {
                transaction
                    .execute("SELECT id FROM items WHERE id=2 FOR UPDATE")
                    .await
                    .unwrap();
            }
            let _ = transaction.commit().await;
            let state = runtime.state.lock().await;
            assert_eq!(
                state.mysql.isolation.audit()[0]["reset_omission_proven"],
                false,
                "{scenario}"
            );
            assert!(!state.unused_exchanges(ReplaySource::Case).is_empty());
            task.abort();
        }
    })
    .await
    .unwrap();
}
