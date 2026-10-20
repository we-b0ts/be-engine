//! Long dependency tails retain finite obligations after primary stream closure.
use super::*;

async fn metadata(root: &Path, timeout_ms: u64) -> Value {
    let record: Value = serde_json::from_slice(
        &tokio::fs::read(root.join("case-a/dependencies.jsonl"))
            .await
            .unwrap(),
    )
    .unwrap();
    let metadata = serde_json::json!({
        "version":1, "request_timeout_ms":timeout_ms, "idle_ms":60000,
        "elapsed_ms":300, "outcome":"quiet", "inventory_complete":true,
        "completed_refs":[{"protocol":"http", "exchange_id":record["id"]}]
    });
    write_metadata(root, &metadata).await;
    metadata
}

async fn write_metadata(root: &Path, metadata: &Value) {
    tokio::fs::write(
        root.join("case-a/dependency-tail-observation.json"),
        metadata.to_string(),
    )
    .await
    .unwrap();
}

async fn listener(
    runtime: &Arc<ReplayRuntime>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let replay = runtime.clone();
    (
        address,
        tokio::spawn(async move { replay.run_tcp(listener).await }),
    )
}

async fn dependency(address: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"POST /tail/case-a HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    read_head(&mut stream).await;
    stream
}

async fn process_rule(runtime: &Arc<ReplayRuntime>) {
    runtime.state.lock().await.dependency_tails =
        crate::replay::control::dependency_tail::CaseTails::with_process_rules(vec![
            crate::BackgroundDependencyRuleConfig::Http {
                name: "process-http".into(),
                authorities: vec!["dependency.test".into()],
                methods: vec!["POST".into()],
                path_prefixes: vec!["/tail/".into()],
                source_revision: String::new(),
                source_evidence: "the process sends periodic work independently of API requests"
                    .into(),
            },
        ]);
}

#[tokio::test]
async fn long_tail_waits_for_real_delayed_http_work_without_repeating_source_idle() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 2000).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let (address, serving) = listener(&runtime).await;
    let ending_state = runtime.state.clone();
    let started = tokio::time::Instant::now();
    let ending =
        tokio::spawn(async move { end_case(&command("end", "case-a"), ending_state).await });
    // The primary response is over and the old attribution window also expires.
    // Only the finite recorded obligation keeps this exact case admitted.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!ending.is_finished());
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some("case-a")
    );
    let mut stream = dependency(address).await;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.ends_with(b"0\r\n\r\n"));
    let ended = tokio::time::timeout(Duration::from_secs(1), ending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended["ok"], true, "{ended}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(runtime.state.lock().await.active_case_id.is_none());
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .snapshot_report()
            .matched_http_exchanges
            .len(),
        1
    );
    serving.abort();
}

#[tokio::test]
async fn http_delivery_outlives_interaction_cleanup_under_the_tail_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 2000).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let (address, serving) = listener(&runtime).await;
    let mut stream = dependency(address).await;
    let reading = tokio::spawn(async move {
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"0\r\n\r\n"));
    });
    let ended = end_case(&command("end", "case-a"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], true, "{ended}");
    reading.await.unwrap();
    assert!(runtime.state.lock().await.active_case_id.is_none());
    serving.abort();
}

#[tokio::test]
async fn a_missing_http_call_remains_dirty_and_retains_the_case() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 180).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let ended = end_case(&command("end", "case-a"), runtime.state.clone()).await;
    assert_eq!(ended["ok"], false);
    assert_eq!(ended["dirty"], true);
    assert!(
        ended["error"]
            .as_str()
            .unwrap()
            .contains("absolute request budget")
    );
    let state = runtime.state.lock().await;
    assert_eq!(state.active_case_id.as_deref(), Some("case-a"));
    let report = state.snapshot_report();
    assert!(report.matched_http_exchanges.is_empty());
    assert_eq!(report.unused_case_http_exchanges.len(), 2);
}

#[tokio::test]
async fn source_proven_process_work_is_not_fabricated_to_satisfy_a_tail() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), 30).await;
    metadata(temp.path(), 2000).await;
    process_rule(&runtime).await;
    assert_eq!(
        begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
        true
    );
    let started = tokio::time::Instant::now();
    let ended = end_case(&command("end", "case-a"), runtime.state.clone()).await;
    // Runtime retains unused evidence for normal report reclassification. This
    // proof removes only the wait; it never invents a successful Target call.
    assert_eq!(ended["dirty"], true);
    assert!(started.elapsed() < Duration::from_secs(1));
    let state = runtime.state.lock().await;
    assert!(state.active_case_id.is_none());
    assert!(state.snapshot_report().matched_http_exchanges.is_empty());
    assert_eq!(state.snapshot_report().unused_case_http_exchanges.len(), 2);
}

#[tokio::test]
async fn legacy_selected_calls_remain_strict_when_a_general_tail_and_process_rule_exist() {
    for selected_in_general_inventory in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let runtime = runtime(temp.path(), 30).await;
        let mut general = metadata(temp.path(), 180).await;
        let reference = general["completed_refs"][0].clone();
        if !selected_in_general_inventory {
            general["completed_refs"] = serde_json::json!([]);
            write_metadata(temp.path(), &general).await;
        }
        tokio::fs::write(
            temp.path().join("case-a/api-origin-observation.json"),
            serde_json::json!({
                "version":1, "request_timeout_ms":10000, "inventory_complete":true,
                "selected_completed_refs":[reference]
            })
            .to_string(),
        )
        .await
        .unwrap();
        process_rule(&runtime).await;
        assert_eq!(
            begin_case(&command("begin", "case-a"), runtime.state.clone()).await["ok"],
            true
        );
        let started = tokio::time::Instant::now();
        let ended = end_case(&command("end", "case-a"), runtime.state.clone()).await;
        assert_eq!(ended["ok"], false, "{ended}");
        assert_eq!(ended["dirty"], true);
        assert!(
            ended["error"]
                .as_str()
                .unwrap()
                .contains("absolute request budget")
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the general tail retains its own absolute budget"
        );
        let state = runtime.state.lock().await;
        assert_eq!(state.active_case_id.as_deref(), Some("case-a"));
        assert!(state.snapshot_report().matched_http_exchanges.is_empty());
        assert_eq!(state.snapshot_report().unused_case_http_exchanges.len(), 2);
    }
}

#[tokio::test]
async fn an_invalid_legacy_inventory_cannot_hide_behind_a_valid_general_tail() {
    for problem in ["absent", "incomplete", "duplicate", "version"] {
        let temp = tempfile::tempdir().unwrap();
        let runtime = runtime(temp.path(), 30).await;
        let general = metadata(temp.path(), 2000).await;
        let reference = general["completed_refs"][0].clone();
        let mut legacy = serde_json::json!({
            "version":1,"request_timeout_ms":10000,"inventory_complete":true,
            "selected_completed_refs":[reference]
        });
        match problem {
            "absent" => {
                legacy["selected_completed_refs"][0]["exchange_id"] =
                    uuid::Uuid::new_v4().to_string().into()
            }
            "incomplete" => legacy["inventory_complete"] = false.into(),
            "duplicate" => {
                let reference = legacy["selected_completed_refs"][0].clone();
                legacy["selected_completed_refs"]
                    .as_array_mut()
                    .unwrap()
                    .push(reference);
            }
            "version" => legacy["version"] = 2.into(),
            _ => unreachable!(),
        }
        tokio::fs::write(
            temp.path().join("case-a/api-origin-observation.json"),
            legacy.to_string(),
        )
        .await
        .unwrap();
        process_rule(&runtime).await;
        let began = begin_case(&command("begin", "case-a"), runtime.state.clone()).await;
        assert_eq!(began["ok"], false, "{problem}: {began}");
        assert!(runtime.state.lock().await.active_case_id.is_none());
    }
}

#[tokio::test]
async fn invalid_or_foreign_tail_inventories_reject_begin_without_legacy_fallback() {
    for problem in [
        "version",
        "deadline",
        "incomplete",
        "duplicate",
        "absent",
        "foreign",
        "zero_budget",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let runtime = runtime(temp.path(), 30).await;
        let mut metadata = metadata(temp.path(), 2000).await;
        // A valid legacy file must not conceal a broken new inventory.
        tokio::fs::write(
            temp.path().join("case-a/api-origin-observation.json"),
            serde_json::json!({"version":1,"request_timeout_ms":2000,"selected_completed_refs":[]})
                .to_string(),
        )
        .await
        .unwrap();
        match problem {
            "version" => metadata["version"] = 2.into(),
            "deadline" => metadata["outcome"] = "request_deadline".into(),
            "incomplete" => metadata["inventory_complete"] = false.into(),
            "duplicate" => {
                let reference = metadata["completed_refs"][0].clone();
                metadata["completed_refs"]
                    .as_array_mut()
                    .unwrap()
                    .push(reference);
            }
            "absent" => {
                metadata["completed_refs"][0]["exchange_id"] =
                    uuid::Uuid::new_v4().to_string().into()
            }
            "foreign" => {
                let record: Value = serde_json::from_slice(
                    &tokio::fs::read(temp.path().join("case-b/dependencies.jsonl"))
                        .await
                        .unwrap(),
                )
                .unwrap();
                metadata["completed_refs"][0]["exchange_id"] = record["id"].clone();
            }
            "zero_budget" => metadata["request_timeout_ms"] = 0.into(),
            _ => unreachable!(),
        }
        write_metadata(temp.path(), &metadata).await;
        let began = begin_case(&command("begin", "case-a"), runtime.state.clone()).await;
        assert_eq!(began["ok"], false, "{problem}: {began}");
        assert!(runtime.state.lock().await.active_case_id.is_none());
    }
}
