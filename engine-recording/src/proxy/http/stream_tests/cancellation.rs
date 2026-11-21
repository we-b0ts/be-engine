use super::*;

#[tokio::test]
async fn dependency_client_cancellation_retains_response_prefix_without_failing_capture() {
    tokio::time::timeout(Duration::from_secs(4), capture_cancelled_stream(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn engine_reset_of_dependency_stream_cannot_certify_client_cancellation() {
    tokio::time::timeout(Duration::from_secs(4), capture_cancelled_stream(true))
        .await
        .unwrap();
}

async fn capture_cancelled_stream(engine_reset: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.recording.case_dependency_post_response_window_ms = 0;
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "cancelled-stream".into(),
        uri_group: None,
    };
    let case_guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&case_guard).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n").await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(super::super::run_with_listener(state.clone(), listener));
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(
            format!("GET http://{authority}/stream HTTP/1.1\r\nHost: {authority}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(client.read_u8().await.unwrap());
    }
    let mut chunk = [0; 8];
    client.read_exact(&mut chunk).await.unwrap();
    assert_eq!(&chunk, b"3\r\none\r\n");
    tokio::time::sleep(Duration::from_millis(60)).await;
    if engine_reset {
        state.dependency_connections().reset_open_connections();
    } else {
        crate::dependency::termination::ConnectionControl::new(&client)
            .unwrap()
            .reset()
            .unwrap();
    }
    drop(client);
    source.await.unwrap();
    let drain = state.drain_active_case_dependencies(case.id).await;
    if engine_reset {
        assert!(drain.is_some() || state.active_case_invalidation(case.id).is_some());
        drop(case_guard);
        proxy.abort();
        return;
    }
    assert!(drain.is_none());
    assert!(state.active_case_invalidation(case.id).is_none());
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().flush_traffic().await.unwrap();
    let case_dir = state.recorder().case_dir(&case);
    let scope: crate::dependency::observation::ScopeIndex = serde_json::from_slice(
        &tokio::fs::read(case_dir.join("dependency-scope.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        tokio::fs::canonicalize(case_dir.join(scope.run_relpath))
            .await
            .unwrap(),
        tokio::fs::canonicalize(state.recorder().run_dir.as_ref())
            .await
            .unwrap(),
        "publishing an ungrouped case must preserve the scope's central-ledger address"
    );
    assert!(!case_dir.join("dependencies.jsonl").exists());
    let raw = crate::recorder::test_io::read_to_string(case_dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    let record: Value = serde_json::from_str(raw.trim()).unwrap();
    let outcome: crate::DependencyExchangeOutcome =
        serde_json::from_value(record["outcome"].clone()).unwrap();
    assert!(outcome.is_client_terminated());
    assert!(outcome.termination().is_some());
    assert_eq!(record["response_body"]["data"], "b25l");
    assert_eq!(record["response_stream"]["version"], 2);
    assert_eq!(record["response_stream"]["complete"], true);
    assert!(record["error"].is_null());
    assert_eq!(record["duration_ms"], record["response_stream"]["end_ms"]);
    drop(case_guard);
    proxy.abort();
}
