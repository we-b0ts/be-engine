//! A failed primary status abandons success-only waits, never real I/O or dirty evidence.
use super::tail::{dependency, listener, metadata};
use super::*;

async fn mark_failed(state: &Arc<Mutex<ReplayState>>, case: &str) {
    let (reply, stop) =
        handle_control_request(command("case_failed", case), state.clone(), None, None).await;
    assert_eq!(reply["ok"], true, "{reply}");
    assert!(!stop);
}

#[tokio::test]
async fn primary_failure_leaves_unstarted_dependencies_unused_and_publishes_complete_dirty_replay()
{
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 900_000).await;
    let report = temp.path().join("report.json");
    for case in ["case-a", "case-b"] {
        assert_eq!(
            begin_case(&command("begin", case), runtime.state.clone()).await["ok"],
            true
        );
        mark_failed(&runtime.state, case).await;
        let deadline = runtime
            .state
            .lock()
            .await
            .case_cleanup
            .deadline(case)
            .unwrap();
        mark_failed(&runtime.state, case).await;
        assert_eq!(
            runtime.state.lock().await.case_cleanup.deadline(case),
            Some(deadline)
        );
        let mut end = command("end", case);
        end.fail_on_dirty = true;
        let ended = tokio::time::timeout(
            Duration::from_secs(1),
            end_case(&end, runtime.state.clone()),
        )
        .await
        .unwrap();
        assert_eq!(ended["ok"], false);
        assert_eq!(ended["dirty"], true);
        assert!(runtime.state.lock().await.active_case_id.is_none());
        assert_eq!(
            runtime.state.lock().await.cases[case].status,
            ReplayCaseStatus::Ended
        );
    }
    let mut finalize = command("finalize", "case-b");
    finalize.fail_on_dirty = false;
    let (reply, stop) =
        handle_control_request(finalize, runtime.state.clone(), Some(report.clone()), None).await;
    assert!(stop, "{reply}");
    assert_eq!(reply["complete"], true);
    assert_eq!(reply["dirty"], true);
    let report: Value = serde_json::from_slice(&tokio::fs::read(report).await.unwrap()).unwrap();
    assert_eq!(report["finalized"], true);
    assert_eq!(report["matched_http_exchange_count"], 0);
    assert_eq!(
        report["unused_case_http_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn primary_failure_still_waits_for_an_actual_http_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 900_000).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let (address, serving) = listener(&runtime).await;
    let mut stream = dependency(address).await;
    runtime
        .state
        .lock()
        .await
        .case_dependency_post_response_window = Duration::ZERO;
    mark_failed(&runtime.state, "case-a").await;
    let state = runtime.state.clone();
    let ending = tokio::spawn(async move { end_case(&command("end", "case-a"), state).await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(!ending.is_finished());
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some("case-a")
    );
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.ends_with(b"0\r\n\r\n"));
    let ended = tokio::time::timeout(Duration::from_secs(1), ending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(runtime.state.lock().await.active_case_id.is_none());
    serving.abort();
}

#[tokio::test]
async fn failed_cleanup_timeout_keeps_actual_io_and_case_ownership_visible() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 900_000).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let (address, serving) = listener(&runtime).await;
    let mut stream = dependency(address).await;
    mark_failed(&runtime.state, "case-a").await;
    let error = crate::replay::control::case_cleanup::drain_started(
        &runtime.state,
        "case-a",
        Some(tokio::time::Instant::now() + Duration::from_millis(30)),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("started dependency cleanup timed out")
    );
    let error = error.to_string();
    let pending: Value = serde_json::from_str(error.split_once("pending=").unwrap().1).unwrap();
    assert_eq!(pending["http"]["count"], 1);
    assert_eq!(pending["http"]["references"][0]["case_id"], "case-a");
    assert_eq!(pending["http"]["references"][0]["status"], "Responding");
    assert_eq!(pending["mysql"]["count"], 0);
    assert!(!error.contains("dependency.test"));
    assert!(!error.contains("/tail/"));
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some("case-a")
    );
    assert_eq!(
        begin_case(&command("begin", "case-b"), runtime.state.clone()).await["ok"],
        false
    );
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        end_case(&command("end", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    serving.abort();
}

#[tokio::test]
async fn absolute_cleanup_timeout_exposes_pending_io_before_target_shutdown() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 100).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let (address, serving) = listener(&runtime).await;
    let mut stream = dependency(address).await;
    runtime
        .state
        .lock()
        .await
        .case_dependency_post_response_window = Duration::ZERO;
    let ended = end_case(&command("end", "case-a"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], false, "{ended}");
    let error = ended["error"].as_str().unwrap();
    let pending: Value = serde_json::from_str(error.split_once("pending=").unwrap().1).unwrap();
    assert_eq!(pending["http"]["count"], 1);
    assert_eq!(pending["http"]["references"][0]["case_id"], "case-a");
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some("case-a")
    );
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.ends_with(b"0\r\n\r\n"));
    serving.abort();
}

#[tokio::test]
async fn execution_status_ignores_unused_inventory_and_exposes_actual_rejection() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let (clean, _) = handle_control_request(
        command("case_execution_status", "case-a"),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(
        clean["failed"], false,
        "unused Source dependencies are accounting evidence"
    );
    let (address, serving) = listener(&runtime).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"POST /unmatched HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502"));
    let (failed, _) = handle_control_request(
        command("case_execution_status", "case-a"),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(failed["failed"], true, "{failed}");
    assert!(
        failed["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure["protocol"] == "http")
    );
    let (wrong, _) = handle_control_request(
        command("case_execution_status", "case-b"),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(wrong["ok"], false);
    serving.abort();
}
