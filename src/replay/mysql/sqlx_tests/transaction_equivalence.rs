//! Ordinary SQLx transactions prove implicit Source transaction coverage over TLS.
use super::*;

fn records() -> Vec<Value> {
    super::super::transaction_equivalence::tests::records()
}

fn with_setup_observations(mut values: Vec<Value>) -> Vec<Value> {
    let setup = |sequence, sql, before, after| {
        let mut value = values[0].clone();
        value["query_sequence"] = json!(sequence);
        value["sql"] = json!(sql);
        value["server_status_before"] = before;
        value["response"]["server_status"] = json!(after);
        let mut capture = crate::dependency::observation::fixture_capture("case");
        capture.semantic_required = false;
        value["capture"] = serde_json::to_value(capture).unwrap();
        value
    };
    let first = setup(1, "SET NAMES utf8mb4", Value::Null, 2);
    let second = setup(2, "SET time_zone = '+08:00'", json!(2), 2);
    let fourth = setup(4, "SET NAMES utf8mb4", json!(0), 0);
    values.splice(0..0, [first, second]);
    values.insert(3, fourth);
    values
}

fn multi_write_records() -> Vec<Value> {
    let mut values = records();
    values.truncate(4);
    let mut second = values[2].clone();
    second["query_sequence"] = json!(7);
    second["sql"] = json!("UPDATE users SET active=2 WHERE id=1");
    values[3]["query_sequence"] = json!(8);
    values.insert(3, second);
    values
}

#[tokio::test]
async fn reordered_transaction_reports_source_references_through_real_sqlx_delivery() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut values = records();
        values.truncate(4);
        values[1]["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
        let (temp, addr, runtime, task) = fixture(&values, false).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut client = connect(addr, &ca).await;
        let mut tx = client.begin().await.unwrap();
        sqlx::query("UPDATE users SET active=? WHERE id=?")
            .bind(1_i32)
            .bind(1_i32)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM users WHERE id=? FOR UPDATE")
            .bind(1_i32)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let _ = tx.commit().await;
        let state = runtime.state.lock().await;
        let diagnostic = state
            .mysql
            .events
            .unmatched_queries
            .iter()
            .find_map(|query| query.diagnostic.as_ref())
            .expect("transaction failure evidence");
        let comparison = &diagnostic["source_transactions"][0]["member_comparison"];
        assert_eq!(
            comparison["first_difference"]["expected"]["source_query_sequence"],
            5
        );
        assert_eq!(
            comparison["first_difference"]["actual"]["source_query_sequence"],
            6
        );
        assert_eq!(diagnostic["covered_transaction_count"], 0);
        task.abort();
    })
    .await
    .unwrap();
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
        for (policy, observations) in [(false, false), (true, false), (false, true), (true, true)] {
            let values = if observations { with_setup_observations(records()) } else { records() };
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
        let values = multi_write_records();
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
        sqlx::query("UPDATE users SET active=? WHERE id=?")
            .bind(2_i32)
            .bind(1_i32)
            .execute(&mut client)
            .await
            .unwrap();
        sqlx::raw_sql("COMMIT").execute(&mut client).await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.transaction_equivalent_autocommit().is_empty());
        let unused = state.unused_exchanges(ReplaySource::Case);
        assert_eq!(unused.len(), 2);
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
            let values = multi_write_records();
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
            drop(state);
            sqlx::query("UPDATE users SET active=? WHERE id=?")
                .bind(2_i32)
                .bind(1_i32)
                .execute(&mut client)
                .await
                .unwrap();
            let state = runtime.state.lock().await;
            assert_eq!(state.mysql.events.matched_query_count, 3);
            assert!(state.transaction_equivalent_autocommit().is_empty());
            let unused = state.unused_exchanges(ReplaySource::Case);
            assert_eq!(unused.len(), 2, "SET and COMMIT must both remain required");
            assert!(unused.iter().any(|e| e.query_sequence == Some(3)));
            assert!(unused.iter().any(|e| e.query_sequence == Some(8)));
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

#[tokio::test]
async fn concurrent_transactions_match_their_own_commit_in_reverse_completion_order() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut values = records();
        values.truncate(4);
        let mut other = values.clone();
        for record in &mut other {
            record["connection_id"] = json!(Uuid::from_u128(1));
            record["sql"] = json!(record["sql"].as_str().unwrap().replace("id=1", "id=2"));
        }
        values.extend(other);
        let (temp, addr, runtime, task) = fixture(&values, false).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut first = connect(addr, &ca).await;
        let mut second = connect(addr, &ca).await;
        let mut first_tx = first.begin().await.unwrap();
        let mut second_tx = second.begin().await.unwrap();
        for (tx, id) in [(&mut first_tx, 1_i32), (&mut second_tx, 2_i32)] {
            sqlx::query("SELECT id FROM users WHERE id=?")
                .bind(id)
                .fetch_one(&mut **tx)
                .await
                .unwrap();
            sqlx::query("UPDATE users SET active=? WHERE id=?")
                .bind(1_i32)
                .bind(id)
                .execute(&mut **tx)
                .await
                .unwrap();
        }
        second_tx.commit().await.unwrap();
        first_tx.commit().await.unwrap();
        let state = runtime.state.lock().await;
        assert!(
            state.unused_exchanges(ReplaySource::Case).is_empty(),
            "{:?}",
            state.unused_exchanges(ReplaySource::Case)
        );
        assert_eq!(state.transaction_equivalent_autocommit().len(), 2);
        task.abort();
    })
    .await
    .unwrap();
}
