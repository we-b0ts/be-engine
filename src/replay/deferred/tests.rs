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
        identity_pairs: Vec::new(),
        derived_input: None,
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
            runtime.state.lock().await.http_exchanges.len(),
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
        assert_eq!(state.http_exchanges.len(), 2);
        assert_eq!(state.http_events.matched_count, 2);
        assert!(
            state
                .unused_http_exchanges(ReplaySource::Case, false)
                .is_empty()
        );
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
        assert_eq!(fresh.state.lock().await.http_events.matched_count, 0);
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
    assert!(state.http_exchanges.is_empty());
}

#[tokio::test]
async fn complete_mysql_connection_is_classified_at_case_preparation() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path()).await;
    let records = ["COMMIT", "ROLLBACK"].into_iter().enumerate().map(|(index, sql)| json!({
        "event_type":"mysql_exchange", "connection_id":Uuid::nil(), "query_sequence":index + 1,
        "target_addr":"db.test:3306", "database":"app", "username":"user", "command":"COM_QUERY", "sql":sql,
        "response":{"status":"ok", "server_status":0, "affected_rows":0, "last_insert_id":0}
    }).to_string()).collect::<Vec<_>>().join("\n");
    std::fs::write(temp.path().join("a/dependencies.jsonl"), records).unwrap();
    let (runtime, _) = load(temp.path(), true).await;
    assert!(runtime.state.lock().await.mysql.exchanges.is_empty());
    let begin = begin_case(&request("begin", "a"), runtime.state.clone()).await;
    assert_eq!(begin["ok"], true, "{begin}");
    let state = runtime.state.lock().await;
    assert_eq!(state.mysql.exchanges.len(), 2);
    assert_eq!(
        state.mysql.exchanges[1].optional_session,
        Some(mysql::OptionalSessionExchange::Rollback)
    );
}

#[tokio::test]
async fn global_read_prefixes_are_available_to_eager_and_lazy_case_cleanup() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path()).await;
        let read = |seq, before| {
            json!({"event_type":"mysql_exchange",
            "connection_id":Uuid::nil(), "query_sequence":seq, "target_addr":"db.test:3306",
            "database":"app", "username":"user", "command":"COM_QUERY",
            "sql":"SELECT id FROM users", "server_status_before":before,
            "response":{"status":"resultset", "server_status":1,
                "columns":[{"name":"id","family":"integer","sql_type":"INT"}], "rows":[]}})
        };
        let globals = [read(100, 0), read(101, 1), read(200, 0), read(201, 1)];
        std::fs::write(
            temp.path().join("global-dependencies.jsonl"),
            globals
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        for (id, seq) in [("a", 102), ("b", 202)] {
            let mut end = read(seq, 1);
            end["sql"] = json!("COMMIT");
            end["response"] = json!({"status":"ok", "server_status":0,
                "affected_rows":0, "last_insert_id":0});
            std::fs::write(
                temp.path().join(id).join("dependencies.jsonl"),
                end.to_string(),
            )
            .unwrap();
        }
        let (runtime, _) = load(temp.path(), lazy).await;
        for id in ["a", "b"] {
            assert_eq!(
                begin_case(&request("begin", id), runtime.state.clone()).await["ok"],
                true
            );
            assert_eq!(
                end_case(&request("end", id), runtime.state.clone()).await["dirty"],
                false
            );
        }
        let state = runtime.state.lock().await;
        assert_eq!(state.allowed_unused_commits().len(), 2);
        assert_eq!(state.unused_exchanges(ReplaySource::Global).len(), 4);
    }
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
    assert!(runtime.state.lock().await.http_exchanges.is_empty());
    assert!(runtime.state.lock().await.active_case_id.is_none());
    let begin = begin_case(&request("begin", "a"), runtime.state.clone()).await;
    assert_eq!(begin["ok"], true, "{begin}");
    assert_eq!(reader.lock().unwrap().hits, 1);
    worker.abort();
}

#[tokio::test]
async fn reclamation_keeps_inflight_rows_and_stable_report_positions() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path()).await;
    let event = json!({"event_type":"mysql_exchange", "target_host":"db.test", "target_port":3306,
        "database":"app", "username":"user", "command":"COM_QUERY", "sql":"SELECT payload FROM records",
        "response":{"status":"resultset", "rows":[[{"kind":"string", "value":"large-payload"}]]}});
    std::fs::write(temp.path().join("a/dependencies.jsonl"), event.to_string()).unwrap();
    let (runtime, _) = load(temp.path(), true).await;
    assert_eq!(
        begin_case(&request("begin", "a"), runtime.state.clone()).await["ok"],
        true
    );
    runtime.state.lock().await.mysql.exchanges[0].status = ReplayExchangeStatus::Responding;
    assert_eq!(
        end_case(&request("end", "a"), runtime.state.clone()).await["dirty"],
        true
    );
    {
        let mut state = runtime.state.lock().await;
        assert_eq!(state.mysql.exchanges[0].record.response.rows.len(), 1);
        assert_eq!(state.unused_exchanges(ReplaySource::Case)[0].index, 0);
        state.mysql.exchanges[0].status = ReplayExchangeStatus::Consumed;
    }
    assert_eq!(
        begin_case(&request("begin", "b"), runtime.state.clone()).await["ok"],
        true
    );
    let state = runtime.state.lock().await;
    assert_eq!(state.mysql.exchanges.len(), 1);
    assert!(state.mysql.exchanges[0].record.response.rows.is_empty());
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(state.mysql.exchanges[0].case_id.as_deref(), Some("a"));
}
