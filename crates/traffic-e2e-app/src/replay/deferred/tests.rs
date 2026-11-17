use super::*;
use serde_json::json;

async fn fixture(root: &Path) {
    for id in ["a", "b"] {
        http::tests::write_http_case(&root.join(id), "http", "api.test", "/dep", "", id).await;
    }
    super::super::write_test_recording_network_manifest(root);
}

async fn load(root: &Path, lazy: bool) -> (Arc<ReplayRuntime>, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = ReplayConfig {
        case_dir: root.into(),
        selected_case_ids: vec![],
        dns_listen: "127.0.0.1:0".parse().unwrap(),
        tcp_listen: addr,
        fake_cidr: "198.18.0.0/15".into(),
        report_path: Some(root.join(".replay/report.json")),
        session_path: None,
        control_socket_path: None,
        ca_cert_path: None,
        ca_key_path: None,
        policy_path: None,
        http_ignore_query_params: vec![],
        process_owned_dependencies: vec![],
        allowed_unused_http: None,
    };
    let lifecycle = ReplayLifecycleConfig {
        dependency_loading: ReplayDependencyLoading {
            lazy_cases: lazy,
            cache_bytes: 4096,
            ..Default::default()
        },
        ..Default::default()
    };
    (
        Arc::new(
            ReplayRuntime::load_with_lifecycle(
                config,
                "127.0.0.1:0".parse().unwrap(),
                addr,
                lifecycle,
            )
            .await
            .unwrap(),
        ),
        listener,
    )
}

fn request(command: &str, id: &str) -> ReplayControlRequest {
    ReplayControlRequest {
        command: command.into(),
        case_id: Some(id.into()),
        fail_on_dirty: true,
        fail_on_incomplete: false,
        parameters: Default::default(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    }
}

async fn call(addr: SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"POST /dep HTTP/1.1\r\nHost: api.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn lazy_inventory_matches_eager_and_never_replenishes_consumption() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path()).await;
        let (runtime, listener) = load(temp.path(), lazy).await;
        let addr = listener.local_addr().unwrap();
        let before = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
        assert_eq!(before["selected_case_ids"], json!(["a", "b"]));
        assert_eq!(
            runtime.state.lock().await.native.core.exchanges.len(),
            if lazy { 0 } else { 2 }
        );
        let server = runtime.clone();
        let task = tokio::spawn(async move {
            server.run_tcp(listener).await.unwrap();
        });
        for id in ["a", "b"] {
            assert_eq!(
                begin_case(&request("begin", id), runtime.state.clone()).await["ok"],
                true
            );
            assert_eq!(
                begin_case(&request("begin", id), runtime.state.clone()).await["ok"],
                true
            );
            let response = call(addr).await;
            assert!(response.starts_with("HTTP/1.1 200"));
            assert!(response.ends_with(id));
            assert_eq!(
                end_case(&request("end", id), runtime.state.clone()).await["dirty"],
                false
            );
        }
        let state = runtime.state.lock().await;
        assert_eq!(state.native.core.exchanges.len(), 2);
        assert_eq!(state.native.snapshot()["http"].matched_count, 2);
        assert!(state.native.snapshot()["http"].unused_case.is_empty());
        drop(state);
        if lazy {
            assert_eq!(
                begin_case(&request("begin", "a"), runtime.state.clone()).await["ok"],
                false
            );
        }
        task.abort();
        let (fresh, _) = load(temp.path(), lazy).await;
        assert_eq!(
            begin_case(&request("begin", "a"), fresh.state.clone()).await["ok"],
            true
        );
        assert_eq!(
            fresh
                .state
                .lock()
                .await
                .native
                .snapshot()
                .get("http")
                .map_or(0, |report| report.matched_count),
            0
        );
    }
}

#[tokio::test]
async fn modified_source_fails_preparation_without_activating_case() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path()).await;
    let (runtime, _) = load(temp.path(), true).await;
    std::fs::write(temp.path().join("a/dependencies.jsonl"), "{}\n").unwrap();
    assert_eq!(
        begin_case(&request("begin", "a"), runtime.state.clone()).await["ok"],
        false
    );
    let state = runtime.state.lock().await;
    assert!(state.active_case_id.is_none());
    assert!(state.native.core.exchanges.is_empty());
}

#[tokio::test]
async fn lazy_startup_indexes_preloaded_redis_before_any_case_begins() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path()).await;
    let record = json!({
        "event_type":"redis_exchange", "connection_id":Uuid::nil(), "sequence":1,
        "target_host":"redis.test", "target_port":6379, "database":0, "resp_version":2,
        "command":"GET",
        "args":[{"encoding":"base64","data":"a2V5","truncated":false}],
        "response":{"encoding":"base64","data":"JDENCnYNCg==","truncated":false},
        "response_kind":"bulk", "outcome":"response", "duration_ms":0, "replay_safe":true
    });
    std::fs::write(temp.path().join("a/dependencies.jsonl"), record.to_string()).unwrap();
    let (runtime, _) = load(temp.path(), true).await;
    let state = runtime.state.lock().await;
    assert!(state.active_case_id.is_none());
    assert_eq!(
        state
            .native
            .core
            .exchanges
            .iter()
            .filter(|exchange| exchange.source.case_id.as_deref() == Some("a"))
            .count(),
        1
    );
}

#[tokio::test]
async fn mysql_transactions_enter_the_same_finite_inventory_at_case_preparation() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path()).await;
    let records = ["COMMIT", "ROLLBACK"].into_iter().enumerate().map(|(index, sql)| json!({
        "event_type":"mysql_exchange", "connection_id":Uuid::nil(), "query_sequence":index + 1,
        "target_addr":"db.test:3306", "database":"app", "username":"user", "command":"COM_QUERY", "sql":sql,
        "response":{"status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0}
    }).to_string()).collect::<Vec<_>>().join("\n");
    std::fs::write(temp.path().join("a/dependencies.jsonl"), records).unwrap();
    let (runtime, _) = load(temp.path(), true).await;
    assert!(runtime.state.lock().await.native.core.exchanges.is_empty());
    let begin = begin_case(&request("begin", "a"), runtime.state.clone()).await;
    assert_eq!(begin["ok"], true, "{begin}");
    let state = runtime.state.lock().await;
    assert_eq!(state.native.core.exchanges.len(), 2);
    assert!(
        state
            .native
            .core
            .exchanges
            .iter()
            .all(|exchange| exchange.native.reference.protocol() == "mysql")
    );
}

#[tokio::test]
async fn read_ahead_warms_bytes_without_installing_exchanges() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path()).await;
    let (runtime, _) = load(temp.path(), true).await;
    assert!(
        prefetch::enqueue(runtime.state.clone(), Some("a"))
            .await
            .unwrap()
    );
    let state = runtime.state.clone();
    let worker = tokio::spawn(async move {
        prefetch::run(state).await.unwrap();
    });
    let reader = runtime
        .state
        .lock()
        .await
        .deferred
        .as_ref()
        .unwrap()
        .reader
        .clone();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while reader.lock().unwrap().source_bytes == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(runtime.state.lock().await.native.core.exchanges.is_empty());
    assert!(runtime.state.lock().await.active_case_id.is_none());
    let begin = begin_case(&request("begin", "a"), runtime.state.clone()).await;
    assert_eq!(begin["ok"], true, "{begin}");
    assert_eq!(reader.lock().unwrap().hits, 2);
    worker.abort();
}
