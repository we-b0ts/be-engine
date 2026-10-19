//! Mixed Accept headers cannot turn an ordinary JSON body into empty SSE evidence.

use super::*;

#[tokio::test]
async fn mixed_accept_json_response_rejects_stream_recording_instead_of_publishing_empty_events() {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new(config(temp.path(), listener.local_addr().unwrap()))
        .await
        .unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        let body = r#"{"result":"ordinary JSON must not disappear"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let (address, recording) = gateway(state.clone()).await;
    timeout(Duration::from_secs(3), async {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{address}/mcp"))
                    .header("accept", "application/json, text/event-stream")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::BAD_GATEWAY);
        response.into_body().collect().await.unwrap();
        source.await.unwrap();
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        state.recorder().flush_traffic().await.unwrap();
        let mut published = Vec::new();
        find_cases(&state.recorder().run_dir.join("apis"), &mut published);
        assert!(
            published.is_empty(),
            "JSON must not become a successful empty SSE case"
        );
        let errors =
            std::fs::read_to_string(state.recorder().run_dir.join("errors.jsonl")).unwrap();
        let errors: Vec<Value> = errors
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(errors.len(), 1);
        let detail: Value = serde_json::from_slice(
            &std::fs::read(
                state
                    .recorder()
                    .run_dir
                    .join(errors[0]["detail_path"].as_str().unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(detail["reason"], "primary_stream_content_type_unsupported");
    })
    .await
    .expect("unsupported stream response must fail promptly");
    recording.abort();
}
