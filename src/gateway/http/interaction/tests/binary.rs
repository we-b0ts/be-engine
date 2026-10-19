use super::*;

#[tokio::test]
async fn binary_download_keeps_ordinary_http_lifecycle_without_raw_opt_in() {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new(config(temp.path(), listener.local_addr().unwrap()))
        .await
        .unwrap();
    assert!(!state.config().http_gateway.record_raw_streaming);
    let source = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x00\xff\x01\x0a").await.unwrap();
    });
    let (address, gateway) = gateway(state.clone()).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = timeout(
        Duration::from_secs(2),
        client.request(
            Request::builder()
                .uri(format!("http://{address}/download"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"\x00\xff\x01\x0a");
    source.await.unwrap();
    let case = published(&state).await;
    let request: Value =
        serde_json::from_slice(&std::fs::read(case.join("request.json")).unwrap()).unwrap();
    assert!(request.get("interaction").is_none());
    assert_eq!(state.recording_lifecycle_phase(), "running");
    gateway.abort();
}
