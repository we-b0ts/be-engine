//! Observed client cancellation is replayable independently of business completion.

use super::*;

#[tokio::test]
async fn cancelling_primary_sse_records_pending_business_and_preserves_source() {
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
        let mut client = primary_client(address, "data: first\n\n").await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        crate::dependency::termination::ConnectionControl::new(&client).unwrap().reset().unwrap();
        client.shutdown().await.ok();

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
        let case = published(&state).await;
        let expected: Value =
            serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
                .unwrap();
        assert_eq!(expected["interaction"]["end"]["reason"], "client_close");
        assert_eq!(expected["interaction"]["end"]["clean"], true);
        assert_eq!(
            expected["interaction"]["end"]["pending"],
            serde_json::json!([0])
        );
        let input: Value = serde_json::from_slice(
            &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            input["interaction"]["actions"][0]["after"],
            serde_json::json!([])
        );
        assert!(
            input["interaction"]["actions"][0]
                .get("gap_start_ms")
                .is_none()
        );
        assert!(!*state.inner.interactions.source_stop.borrow());
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            read_head(&mut socket).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n").await.unwrap();
            let mut rest = Vec::new();
            assert_eq!(socket.read_to_end(&mut rest).await.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset);
            assert!(rest.is_empty());
        });
        let actual = replay_case(&case, target_address).await;
        assert_eq!(actual.end.reason, crate::interaction::model::EndReason::ClientClose);
        assert_eq!(actual.end.pending, vec![0]);
        assert!(actual.end.clean);
        target.await.unwrap();
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
        let client = primary_client(address, "event: done\ndata: ok\n\n").await;
        crate::dependency::termination::ConnectionControl::new(&client).unwrap().reset().unwrap();
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

async fn primary_client(address: SocketAddr, first: &str) -> tokio::net::TcpStream {
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(format!("POST /events HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let mut length = Vec::new();
    while !length.ends_with(b"\r\n") {
        length.push(client.read_u8().await.unwrap());
    }
    let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap().trim(), 16).unwrap();
    assert_eq!(length, first.len());
    let mut chunk = vec![0; length + 2];
    client.read_exact(&mut chunk).await.unwrap();
    assert_eq!(chunk, format!("{first}\r\n").as_bytes());
    client
}

#[tokio::test]
async fn primary_http_client_fin_preserves_delayed_complete_stream() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    settings.http_gateway.interaction.business_idle_ms = 1_000;
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        read_head(&mut socket).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nd\r\ndata: first\n\n\r\n0\r\n\r\n").await.unwrap();
    });
    let (address, recording) = gateway(state.clone()).await;
    timeout(Duration::from_secs(3), async {
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(format!("GET /events HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(String::from_utf8_lossy(&response).contains("data: first\n\n"));
        let case = published(&state).await;
        let expected: Value = serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap()).unwrap();
        assert_eq!(expected["interaction"]["end"]["reason"], "server_eof");
        assert_eq!(expected["interaction"]["end"]["clean"], true);
        let input: Value = serde_json::from_slice(&crate::request_headers::load_request_file(&case.join("request.json")).unwrap()).unwrap();
        assert_eq!(input["interaction"]["actions"], serde_json::json!([]));
    }).await.unwrap();
    source.await.unwrap();
    recording.abort();
}

#[tokio::test]
async fn cancelling_within_sse_message_preserves_plaintext_prefix_and_self_replays() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    settings.http_gateway.interaction.request_timeout_ms = 10_000;
    settings.http_gateway.interaction.max_duration_ms = 30_000;
    let state = AppState::new(settings).await.unwrap();
    const PREFIX: &str = "data: first\n\ndata: unfinished\n";
    let source = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        read_head(&mut socket).await;
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{PREFIX}\r\n", PREFIX.len()).as_bytes()).await.unwrap();
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    });
    let (address, recording) = gateway(state.clone()).await;
    timeout(Duration::from_secs(3), async {
        let client = primary_client(address, PREFIX).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        crate::dependency::termination::ConnectionControl::new(&client).unwrap().reset().unwrap();
        source.await.unwrap();
        let case = published(&state).await;
        let expected_path = case.join("expected-response.json");
        let mut expected: Value = serde_json::from_slice(&std::fs::read(&expected_path).unwrap()).unwrap();
        let stored: crate::interaction::model::WireMessage = serde_json::from_value(expected["interaction"]["end"]["partial_message"].clone()).unwrap();
        assert_eq!(stored.decode().unwrap(), b"data: unfinished\n");
        assert!(expected.get("private_interaction_output").is_none());
        crate::interaction::private::decrypt_output(&mut expected, &expected_path).unwrap();
        let output: OutputObservation = serde_json::from_value(expected["interaction"].clone()).unwrap();
        assert_eq!(output.end.partial_message.unwrap().decode().unwrap(), b"data: unfinished\n");
        assert!(output.end.clean);
        assert_eq!(output.end.pending, vec![0]);
        assert!(!*state.inner.interactions.source_stop.borrow());

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            read_head(&mut socket).await;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{PREFIX}\r\n", PREFIX.len()).as_bytes()).await.unwrap();
            let error = socket.read_to_end(&mut Vec::new()).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        });
        let actual = replay_case(&case, address).await;
        assert_eq!(actual.end.partial_message.unwrap().decode().unwrap(), b"data: unfinished\n");
        target.await.unwrap();
        let actual_path = case.join("test-actual.json");
        let mut altered: Value = serde_json::from_slice(&std::fs::read(&actual_path).unwrap()).unwrap();
        altered["interaction"]["end"]["partial_message"] = serde_json::to_value(crate::interaction::model::WireMessage::binary(b"data: different\n")).unwrap();
        std::fs::write(&actual_path, serde_json::to_vec(&altered).unwrap()).unwrap();
        let report = crate::replay::assert_recorded_response(crate::replay::ResponseAssertionOptions {
            case_id: "different-partial-prefix".into(),
            request: case.join("request.json"), expected_response: expected_path,
            actual_response: actual_path, policy: case.join("test-policy.yaml"),
        }).unwrap();
        assert!(!report.passed);
        assert!(report.differences.iter().any(|difference| difference.pointer == "$interaction/end/partial_message"));
    }).await.expect("mid-message cancellation must publish without waiting for Source business completion");
    recording.abort();
}
