//! Real TLS clients copy historical read fields through a separate write client.
use super::*;
use sqlx::Executor;

fn policy() -> &'static str {
    r#"format: traffic-policy/v3
json:
  fields:
    /createdAt: {kind: time, formats: [iso8601_naive]}
    /updatedAt: {kind: time, formats: [iso8601_naive]}
"#
}
fn payload(updated: &str) -> Value {
    json!({"createdAt":"2010-01-01T00:00:00","updatedAt":updated,"stable":"kept"})
}
fn records(count: usize, delay: u64) -> Vec<Value> {
    let mut records = Vec::new();
    let reader = uuid::Uuid::new_v4();
    let writer = uuid::Uuid::new_v4();
    for index in 1..=count {
        let mut read = exchange(
            &format!("SELECT payload FROM tasks WHERE id={index}"),
            result(
                json!([{"name":"payload","database":"appdb","table":"tasks","column":"payload","family":"string","sql_type":"VARCHAR"}]),
                json!([[{"kind":"string","value":payload("2019-01-01T00:00:00").to_string()}]]),
            ),
        );
        read["connection_id"] = json!(reader);
        read["query_sequence"] = json!(index);
        read["duration_ms"] = json!(delay);
        let mut write = exchange(
            &format!(
                "UPDATE tasks SET payload='{}' WHERE id={index}",
                payload("2020-01-01T00:00:01")
            ),
            json!({"status":"ok","affected_rows":1}),
        );
        write["connection_id"] = json!(writer);
        write["query_sequence"] = json!(index);
        records.extend([read, write]);
    }
    records
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn historical_read_then_immediate_write_on_another_connection_is_repeatable() {
    tokio::time::timeout(Duration::from_secs(20), async {
        const COUNT: usize = 64;
        let (temp, addr, runtime, task) =
            fixture_with_policy(&records(COUNT, 0), Some(policy())).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut reader = connect(addr, &ca).await;
        let mut writer = connect(addr, &ca).await;
        let original = std::fs::read(
            temp.path()
                .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl"),
        )
        .unwrap();
        for index in 1..=COUNT {
            let row = reader
                .fetch_one(format!("SELECT payload FROM tasks WHERE id={index}").as_str())
                .await
                .unwrap();
            let mut document: Value = serde_json::from_str(row.get::<&str, _>("payload")).unwrap();
            let created = document["createdAt"].as_str().unwrap();
            assert!(chrono::NaiveDateTime::parse_from_str(created, "%Y-%m-%dT%H:%M:%S%.f").is_ok());
            // Preserve the actual materialized historical value on the later
            // write; authorization comes from this completed read delivery.
            let delivered_created = document["createdAt"].clone();
            let observed = Utc::now();
            runtime.state.lock().await.mysql.observed_at_for_test = Some(observed);
            document["updatedAt"] = json!(
                (observed + chrono::Duration::seconds(1))
                    .format("%Y-%m-%dT%H:%M:%S%.6f")
                    .to_string()
            );
            assert_eq!(document["createdAt"], delivered_created);
            let result = sqlx::query("UPDATE tasks SET payload=? WHERE id=?")
                .bind(document.to_string())
                .bind(index as i64)
                .execute(&mut writer)
                .await;
            assert_eq!(result.unwrap().rows_affected(), 1, "iteration {index}");
        }
        reader.close().await.unwrap();
        writer.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, COUNT * 2);
        assert!(state.mysql.events.unmatched_queries.is_empty());
        let manifest = state
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .witness_manifest()
            .unwrap();
        let witnesses = manifest.witnesses().unwrap();
        let delivered = witnesses
            .iter()
            .filter(|witness| {
                witness.metadata.target_role == crate::policy_evidence::TargetRole::DeliveredInput
            })
            .collect::<Vec<_>>();
        assert_eq!(
            delivered.len(),
            COUNT,
            "each successful read retains its actual input fact"
        );
        assert!(
            delivered
                .iter()
                .all(|witness| witness.target_sha256.is_some()
                    && witness.metadata.clocks.delivery.source.is_some()
                    && witness.metadata.clocks.delivery.target.is_some())
        );
        assert_eq!(
            std::fs::read(
                temp.path()
                    .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")
            )
            .unwrap(),
            original
        );
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivered_time_facts_are_visible_before_the_async_global_delivery_ledger() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (temp, addr, runtime, task) =
            fixture_with_policy(&records(1, 100), Some(policy())).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut reader = connect(addr, &ca).await;
        let mut writer = connect(addr, &ca).await;
        let reading = tokio::spawn(async move {
            let row = reader
                .fetch_one("SELECT payload FROM tasks WHERE id=1")
                .await
                .unwrap();
            let document: Value = serde_json::from_str(row.get::<&str, _>("payload")).unwrap();
            (reader, document)
        });
        // Hold only in this test: the real read can finish writing its response,
        // while its ordinary async global ledger is deliberately unavailable.
        let ledger = loop {
            let ledger = runtime.state.lock().await;
            if ledger.mysql.exchanges[0].status == ReplayExchangeStatus::Responding {
                break ledger;
            }
            drop(ledger);
            tokio::task::yield_now().await;
        };
        let (reader, mut document) = reading.await.unwrap();
        let owner = &ledger.replay_policy.as_ref().unwrap().request_contracts;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !owner.has_time_copies("case-id") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("wire success must commit copy facts without the global async mutex");
        drop(ledger);
        let observed = Utc::now();
        runtime.state.lock().await.mysql.observed_at_for_test = Some(observed);
        document["updatedAt"] = json!(
            (observed + chrono::Duration::seconds(1))
                .format("%Y-%m-%dT%H:%M:%S%.6f")
                .to_string()
        );
        assert_eq!(
            sqlx::query("UPDATE tasks SET payload=? WHERE id=?")
                .bind(document.to_string())
                .bind(1_i64)
                .execute(&mut writer)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        reader.close().await.unwrap();
        writer.close().await.unwrap();
        task.abort();
    })
    .await
    .unwrap();
}
