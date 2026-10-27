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
        .map(|record| {
            json!({
                "protocol":"mysql", "connection_id":record["connection_id"],
                "sequence":record["query_sequence"]
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        case.join("async-api-observation.json"),
        json!({"version":1,"request_timeout_ms":2000,"end_reason":"resource",
            "complete":true,"inventory_complete":true,"completed_refs":references})
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
async fn permitted_source_setup_and_readonly_rollback_do_not_stall_async_tail() {
    let records = super::autocommit_tests::cold_records();
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let mut client = connect(address, &ca(&temp)).await;
    sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut client)
        .await
        .unwrap();
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let state = runtime.state.lock().await;
    assert!(state.dependency_tails.failures().is_empty());
    assert_eq!(state.mysql.events.matched_query_count, 1);
    assert_eq!(state.allowed_unused_autocommit().len(), 1);
    assert_eq!(state.allowed_unused_rollbacks().len(), 2);
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(
        state
            .mysql
            .exchanges
            .iter()
            .filter(|exchange| exchange.status.is_consumed())
            .count(),
        1
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
async fn a_started_optional_rollback_retains_real_io_until_delivery_finishes() {
    let mut records = super::autocommit_tests::cold_records();
    records[2]["duration_ms"] = json!(250);
    let (temp, address, runtime, serving) = fixture(&records, false).await;
    prepare_tail(&temp, &runtime, &records).await;
    let mut client = connect(address, &ca(&temp)).await;
    sqlx::query("SELECT id FROM users WHERE id=?")
        .bind(1_i32)
        .fetch_one(&mut client)
        .await
        .unwrap();
    let delivery = tokio::spawn(async move {
        sqlx::query("ROLLBACK").execute(&mut client).await.unwrap();
        client
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .state
                .lock()
                .await
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
async fn single_write_commit_omission_requires_actual_successful_target_delivery() {
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
    {
        let state = runtime.state.lock().await;
        let commit = state
            .mysql
            .exchanges
            .iter()
            .position(|exchange| exchange.record.query_sequence == Some(7))
            .unwrap();
        assert!(!state.mysql.permits_unstarted_omission(commit));
    }
    sqlx::query("UPDATE users SET active=? WHERE id=?")
        .bind(1_i32)
        .bind(1_i32)
        .execute(&mut client)
        .await
        .unwrap();
    let ended = end_case(&command("end"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    let state = runtime.state.lock().await;
    assert_eq!(state.allowed_unused_commits().len(), 1);
    assert_eq!(state.transaction_equivalent_autocommit().len(), 1);
    assert_eq!(state.mysql.events.matched_query_count, 2);
    assert!(state.dependency_tails.failures().is_empty());
    serving.abort();
}
