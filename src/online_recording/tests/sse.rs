use super::*;

pub(super) async fn bounded_sse_finalizes_through_relay_and_releases_admission() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source_address = source.local_addr().unwrap();
    let gateway_address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = crate::AppConfig::default();
    config.http.enabled = false;
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_address;
    config.http_gateway.matched_upstream = format!("http://{source_address}");
    config.http_gateway.fallback_upstream = format!("http://{source_address}");
    config.http_gateway.rules = vec![crate::HttpGatewayRuleConfig {
        name: Some("sse".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api/".to_string()],
        ..Default::default()
    }];
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.dns_mock.registry_path = temp.path().join("dns.json");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(2), async {
        while tokio::net::TcpStream::connect(gateway_address)
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let mut fixture = Fixture::new(
        format!("http://{gateway_address}").parse().unwrap(),
        Duration::from_secs(2),
        1024,
    )
    .await;
    fixture.tasks.push(gateway);
    let source = tokio::spawn(async move {
        let (mut stream, _) = source.accept().await.unwrap();
        read_request(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: ready\n\n\r\n").await.unwrap();
        let mut buffer = [0; 1024];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.request("GET", Some("token-1"), ""),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"data: ready\n\n");
    assert_eq!(fixture.releases.load(Ordering::SeqCst), 1);
    assert!(fixture.token.lock().unwrap().is_none());
    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let case_dir = std::fs::read_dir(run_dir.join("apis/api-example"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(case_dir.join("expected-response.json")).unwrap())
            .unwrap();
    assert_eq!(
        expected["sse_observation"]["end"],
        "observation_window_elapsed"
    );
    source.await.unwrap();
}
