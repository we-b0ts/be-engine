//! Client closure is recorded only as success after complete business and framing.

use super::*;

#[tokio::test]
async fn cancelling_silent_primary_sse_closes_upstream_and_fails_without_publication() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    settings.http_gateway.request_timeout_ms = 10_000;
    settings.http_gateway.interaction.request_timeout_ms = 10_000;
    settings.http_gateway.interaction.max_duration_ms = 30_000;
    settings.http_gateway.interaction.cleanup_timeout_ms = 1_000;
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_head(&mut stream).await;
        let first = "data: first\n\n";
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n",
                    first.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        // No EOF, terminal event or subsequent frame can wake the gateway's reader.
        let mut remaining = Vec::new();
        stream.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty(), "Source received unexpected input");
    });
    let (address, recording) = gateway(state.clone()).await;

    timeout(Duration::from_secs(2), async {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{address}/events"))
                    .header("accept", "text/event-stream")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(frame.data_ref().unwrap().as_ref(), b"data: first\n\n");
        drop(body);

        // Cancellation must close the upstream transport without waiting for data.
        source.await.unwrap();
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(1))
                .await,
            "cancelled case retained its ownership guard"
        );
        state.recorder().flush_traffic().await.unwrap();
        let run = &state.recorder().run_dir;
        let mut cases = Vec::new();
        find_cases(&run.join("apis"), &mut cases);
        assert!(
            cases.is_empty(),
            "cancelled stream must never publish a case"
        );

        let errors = std::fs::read_to_string(run.join("errors.jsonl")).unwrap();
        let errors: Vec<Value> = errors
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(errors.len(), 1);
        let detail_path = run.join(errors[0]["detail_path"].as_str().unwrap());
        assert!(detail_path.starts_with(run.join("failed")));
        let detail: Value = serde_json::from_slice(&std::fs::read(detail_path).unwrap()).unwrap();
        assert_eq!(detail["reason"], "interaction_incomplete");
        let report: Value =
            serde_json::from_slice(&std::fs::read(run.join("recording-run.json")).unwrap())
                .unwrap();
        assert_eq!(report["published_cases"], 0);
        assert_eq!(report["failed_cases"], 1);
    })
    .await
    .expect("client cancellation must finish before the 10-second request deadline");
    recording.abort();
}

#[tokio::test]
async fn client_close_after_sse_done_records_close_input_and_preserves_source_service() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    settings.http_gateway.interaction.business_idle_ms = 1_000;
    settings.http_gateway.interaction.stream_terminal =
        Some(crate::interaction::policy::StreamTerminal::SseEvent {
            event: "done".into(),
        });
    let state = AppState::new(settings).await.unwrap();
    let (disconnected, upstream_closed) = oneshot::channel();
    let source = tokio::spawn(async move {
        let mut disconnected = Some(disconnected);
        loop {
            let (mut stream, _) = upstream.accept().await.unwrap();
            read_head(&mut stream).await;
            let event = "event: done\ndata: ok\n\n";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{event}\r\n", event.len()).as_bytes()).await.unwrap();
            // Keep the HTTP response open after the terminal event, until its client closes.
            let mut remaining = Vec::new();
            stream.read_to_end(&mut remaining).await.unwrap();
            assert!(remaining.is_empty());
            if let Some(disconnected) = disconnected.take() {
                disconnected.send(()).unwrap();
            }
        }
    });
    let (address, recording) = gateway(state.clone()).await;
    timeout(Duration::from_secs(2), async {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client.request(Request::builder().uri(format!("http://{address}/events")).header("accept", "text/event-stream").body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        let mut body = response.into_body();
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(frame.data_ref().unwrap().as_ref(), b"event: done\ndata: ok\n\n");
        drop(body);
        upstream_closed.await.unwrap();
        let case = published(&state).await;
        let input: Value = serde_json::from_slice(&crate::request_headers::load_request_file(&case.join("request.json")).unwrap()).unwrap();
        let input: InputTranscript = serde_json::from_value(input["interaction"].clone()).unwrap();
        assert_eq!(input.actions.len(), 1);
        assert!(matches!(&input.actions[0].action, crate::interaction::model::InputActionKind::Close { code: None, reason } if reason.is_empty()));
        assert_eq!(input.actions[0].after, vec![0]);
        assert!(input.actions[0].gap_start_ms.is_some_and(|completed| completed <= input.actions[0].offset_ms));
        assert!(!input.actions[0].compressible_gap);
        let expected: Value = serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap()).unwrap();
        assert_eq!(expected["interaction"]["end"]["reason"], "client_close");
        assert_eq!(expected["interaction"]["end"]["clean"], true);
        assert_eq!(state.recording_lifecycle_phase(), "running");
        assert!(!*state.inner.interactions.source_stop.borrow());
        assert!(!source.is_finished(), "closing one stream must preserve the Source service");
    }).await.expect("a completed client-close case must publish promptly");
    source.abort();
    recording.abort();
}
