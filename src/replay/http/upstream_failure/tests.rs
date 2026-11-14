use super::*;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;

#[tokio::test]
async fn recorded_proxy_failure_replays_the_same_502_and_consumes_one_exact_request() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case");
    let error = "failed to connect to service.test:8080: connection refused";
    super::super::tests::write_http_case(
        &case,
        "http",
        "service.test:8080",
        "/dependency",
        "{}",
        "unused",
    )
    .await;
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/api","timestamp":"2026-07-15T04:30:00Z"}"#,
    )
    .unwrap();
    let path = case.join("dependencies.jsonl");
    let mut event: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    event["outcome"] = "response".into();
    event["error"] = error.into();
    event["response_status"] = Value::Null;
    event["response_headers"] = Value::Null;
    event["response_body"] = Value::Null;
    event["duration_ms"] = 0.into();
    std::fs::write(&path, event.to_string()).unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        "format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [uuid]}\n",
    )
    .unwrap();
    let (address, runtime, task) =
        super::super::tests::spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    let client = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let send = |path: &'static str| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "service.test:8080")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap()
    };
    let response = sender.send_request(send("/dependency")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        error.as_bytes()
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while runtime
            .state
            .lock()
            .await
            .protocols
            .http_events
            .matched_count
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    {
        let state = runtime.state.lock().await;
        assert_eq!(state.protocols.http_events.matched_count, 1);
        assert!(!state.http_case_is_dirty("case"));
        assert!(state.protocols.http_events.unsupported.is_empty());
    }
    let response = sender.send_request(send("/dependency")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    response.into_body().collect().await.unwrap();
    assert!(runtime.state.lock().await.http_case_is_dirty("case"));
    connection.abort();
    task.abort();
}
