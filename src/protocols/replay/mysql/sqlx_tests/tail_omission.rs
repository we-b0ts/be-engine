//! Native omission proofs remain valid in a finite asynchronous Case tail.
use super::*;
use crate::replay::control::{ReplayControlRequest, begin_case, end_case};

fn command(command: &str) -> ReplayControlRequest {
    serde_json::from_value(json!({"command":command,"case_id":"case-id","fail_on_dirty":true}))
        .unwrap()
}

async fn prepare_tail(temp: &tempfile::TempDir, runtime: &ReplayRuntime, records: &[Value]) {
    let case = temp.path().join(".traffic-e2e/local/recordings/case-id");
    let references = records
        .iter()
        .filter(|record| record["command"] != "COM_STMT_PREPARE")
        .map(|record| {
            json!({
                "protocol":"mysql", "connection_id":record["connection_id"],
                "sequence":record["query_sequence"]
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        case.join("async-api-observation.json"),
        json!({"version":2,"request_timeout_ms":2000,"end_reason":"resource",
            "capture_complete":true,"business_complete":true,"business_completion":"observed","inventory_complete":true,"completed_refs":references})
        .to_string(),
    )
    .unwrap();
    {
        let mut state = runtime.state.lock().await;
        state.case_dependency_post_response_window = Duration::ZERO;
        state.dependency_tails = crate::replay::control::dependency_tail::CaseTails::default()
            .with_no_progress_timeout(Duration::from_millis(50));
    }
    let begun = begin_case(&command("begin"), runtime.state.clone()).await;
    assert_eq!(begun["ok"], true, "{begun}");
}

fn ca(temp: &tempfile::TempDir) -> PathBuf {
    temp.path()
        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem")
}

#[tokio::test]
async fn finite_inventory_can_consume_native_setup_and_readonly_cleanup() {
    let records = super::autocommit_tests::cold_records();
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let mut client = connect(address, &ca(&temp)).await;
    sqlx::query("SET AUTOCOMMIT=0")
        .execute(&mut client)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut client)
        .await
        .unwrap();
    sqlx::query("ROLLBACK").execute(&mut client).await.unwrap();
    sqlx::query("ROLLBACK").execute(&mut client).await.unwrap();
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let state = runtime.state.lock().await;
    assert!(state.dependency_tails.failures().is_empty());
    assert_eq!(state.protocols.mysql.events.matched_query_count, 4);
    assert_eq!(state.allowed_unused_autocommit().len(), 0);
    assert_eq!(state.allowed_unused_rollbacks().len(), 0);
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(
        state
            .protocols
            .mysql
            .exchanges
            .iter()
            .filter(|exchange| exchange.status.is_consumed())
            .count(),
        4
    );
    assert_eq!(
        std::fs::read(case_dependencies(&temp)).unwrap(),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .as_bytes()
    );
    serving.abort();
}

fn case_dependencies(temp: &tempfile::TempDir) -> PathBuf {
    temp.path()
        .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl")
}

#[tokio::test]
async fn missing_business_read_stays_dirty_and_is_the_only_pending_reference() {
    let records = super::autocommit_tests::cold_records();
    let (temp, _, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], false, "{ended}");
    let state = runtime.state.lock().await;
    let failures = state.dependency_tails.failures();
    assert_eq!(failures[0]["kind"], "case_no_progress");
    assert!(
        failures[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("recorded dependencies remain unconsumed (pending: 1)")
    );
    let waiting = &failures[0]["waiting"];
    assert_eq!(waiting["pending_source_dependencies"], 1);
    assert_eq!(waiting["references"][0]["reference"]["sequence"], 5);
    assert_eq!(state.unused_exchanges(ReplaySource::Case).len(), 1);
    serving.abort();
}

#[tokio::test]
async fn finite_inventory_accepts_native_readonly_equivalence_without_fabricated_consumption() {
    let records = super::autocommit_tests::cold_records();
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let original = std::fs::read(case_dependencies(&temp)).unwrap();
    let mut client = connect(address, &ca(&temp)).await;
    let row = sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut client)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>("id"), 1);
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let state = runtime.state.lock().await;
    assert!(state.dependency_tails.failures().is_empty());
    assert_eq!(state.protocols.mysql.events.matched_query_count, 1);
    assert_eq!(state.allowed_unused_autocommit().len(), 1);
    assert_eq!(state.allowed_unused_rollbacks().len(), 2);
    assert_eq!(
        state
            .protocols
            .mysql
            .exchanges
            .iter()
            .filter(|exchange| exchange.status.is_consumed())
            .count(),
        1
    );
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(std::fs::read(case_dependencies(&temp)).unwrap(), original);
    serving.abort();
}

#[tokio::test]
async fn finite_inventory_accepts_a_proven_native_autocommit_write_and_its_session_omissions() {
    let mut records = super::autocommit_tests::cold_records();
    records[2]["sql"] = json!("UPDATE users SET active=1 WHERE id=1");
    records[2]["response"] =
        json!({"status":"ok","server_status":1,"affected_rows":1,"last_insert_id":0});
    records[3]["sql"] = json!("COMMIT");
    records[3]["server_status_before"] = json!(1);
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let mut client = connect(address, &ca(&temp)).await;
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
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let state = runtime.state.lock().await;
    assert!(state.dependency_tails.failures().is_empty());
    assert_eq!(state.transaction_equivalent_autocommit().len(), 1);
    assert_eq!(state.allowed_unused_commits().len(), 1);
    assert_eq!(state.protocols.mysql.events.matched_query_count, 2);
    assert_eq!(
        state
            .protocols
            .mysql
            .exchanges
            .iter()
            .filter(|exchange| exchange.status.is_consumed())
            .count(),
        2
    );
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    serving.abort();
}

#[tokio::test]
async fn finite_inventory_accepts_setup_equivalence_after_real_row_lock_and_commit_delivery() {
    let mut records = super::autocommit_tests::cold_records();
    records[1]["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
    records[2]["sql"] = json!("COMMIT");
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let original = std::fs::read(case_dependencies(&temp)).unwrap();
    let mut client = connect(address, &ca(&temp)).await;
    let mut transaction = client.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=? FOR UPDATE")
        .bind(1_i32)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    {
        let state = runtime.state.lock().await;
        assert_eq!(state.transaction_equivalent_autocommit().len(), 0);
        assert_eq!(state.allowed_unused_commits().len(), 0);
    }
    transaction.commit().await.unwrap();
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let state = runtime.state.lock().await;
    assert!(state.dependency_tails.failures().is_empty());
    assert_eq!(state.transaction_equivalent_autocommit().len(), 1);
    assert_eq!(state.allowed_unused_rollbacks().len(), 1);
    assert_eq!(state.protocols.mysql.events.matched_query_count, 2);
    assert_eq!(
        state
            .protocols
            .mysql
            .exchanges
            .iter()
            .filter(|exchange| exchange.status.is_consumed())
            .count(),
        2
    );
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(std::fs::read(case_dependencies(&temp)).unwrap(), original);
    serving.abort();
}

#[tokio::test]
async fn a_started_optional_rollback_retains_real_io_until_delivery_finishes() {
    let mut records = super::autocommit_tests::cold_records();
    records[2]["duration_ms"] = json!(250);
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let mut client = connect(address, &ca(&temp)).await;
    sqlx::query("SET AUTOCOMMIT=0")
        .execute(&mut client)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut client)
        .await
        .unwrap();
    let delivery = tokio::spawn(async move {
        sqlx::query("ROLLBACK").execute(&mut client).await.unwrap();
        sqlx::query("ROLLBACK").execute(&mut client).await.unwrap();
        client
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .protocols
                .mysql
                .exchanges
                .iter()
                .any(|exchange| {
                    exchange.record.query_sequence == Some(6)
                        && exchange.status == ReplayExchangeStatus::Responding
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let started = tokio::time::Instant::now();
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(started.elapsed() >= Duration::from_millis(150));
    let _client = delivery.await.unwrap();
    assert!(
        runtime
            .state
            .lock()
            .await
            .dependency_tails
            .failures()
            .is_empty()
    );
    serving.abort();
}

#[tokio::test]
async fn finite_inventory_requires_the_actual_write_and_commit_delivery() {
    let mut records = super::autocommit_tests::cold_records();
    records[2]["sql"] = json!("UPDATE users SET active=1 WHERE id=1");
    records[2]["response"] =
        json!({"status":"ok","server_status":1,"affected_rows":1,"last_insert_id":0});
    records[3]["sql"] = json!("COMMIT");
    records[3]["server_status_before"] = json!(1);
    // COM_STMT_PREPARE occupies native sequence 4 without executing SQL.
    // Its real control fact closes Source continuity; it is not a tail effect.
    let mut prepare = records[1].clone();
    prepare["command"] = json!("COM_STMT_PREPARE");
    prepare["query_sequence"] = json!(4);
    prepare["statement_id"] = json!(1);
    prepare["sql"] = json!("SELECT id FROM users WHERE id=?");
    prepare["response"] = json!({"status":"stmt_prepare","server_status":0,"columns":[],"rows":[],"rows_truncated":false});
    records.insert(1, prepare);
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let mut client = connect(address, &ca(&temp)).await;
    sqlx::query("SET AUTOCOMMIT=0")
        .execute(&mut client)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut client)
        .await
        .unwrap();
    {
        let state = runtime.state.lock().await;
        let commit = state
            .protocols
            .mysql
            .exchanges
            .iter()
            .position(|exchange| exchange.record.query_sequence == Some(7))
            .unwrap();
        assert!(!state.protocols.mysql.permits_unstarted_omission(commit));
    }
    sqlx::query("UPDATE users SET active=? WHERE id=?")
        .bind(1_i32)
        .bind(1_i32)
        .execute(&mut client)
        .await
        .unwrap();
    sqlx::query("COMMIT").execute(&mut client).await.unwrap();
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    let diagnostic = {
        let state = runtime.state.lock().await;
        (
            state
                .protocols
                .mysql
                .exchanges
                .iter()
                .map(|e| (e.record.query_sequence, e.status))
                .collect::<Vec<_>>(),
            state.dependency_tails.failures(),
        )
    };
    assert_eq!(ended["ok"], true, "{ended}; diagnostic={diagnostic:?}");
    let state = runtime.state.lock().await;
    assert_eq!(state.allowed_unused_commits().len(), 0);
    assert_eq!(state.transaction_equivalent_autocommit().len(), 0);
    assert_eq!(state.protocols.mysql.events.matched_query_count, 4);
    assert!(state.dependency_tails.failures().is_empty());
    serving.abort();
}
