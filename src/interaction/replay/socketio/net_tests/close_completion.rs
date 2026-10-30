//! A namespace's real teardown precedes the next Case, retaining explicit close timing.
use super::*;

fn close_program() -> InputTranscript {
    let mut input = program();
    input.actions[1].after.clear();
    input.actions[1].compressible_gap = false;
    input.actions[1].gap_start_ms = None;
    input.actions[1].offset_ms = 30;
    input.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("41"),
    };
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 40,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("1"),
        },
    });
    input
}

#[tokio::test]
async fn normal_close_waits_for_peer_cleanup_but_dependency_failure_interrupts_that_wait() {
    for reject in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (entered, cleanup_started) = tokio::sync::oneshot::channel();
        let (release, cleanup_release) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket.send(Message::Text(open().into())).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "40"
            );
            socket
                .send(Message::Text("40{\"sid\":\"live\"}".into()))
                .await
                .unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "41"
            );
            // The application owns work after namespace disconnect, before its
            // input loop can consume Engine.IO CLOSE and complete the transport.
            entered.send(()).unwrap();
            cleanup_release.await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "1"
            );
            let _ = socket.send(Message::Close(None)).await;
        });
        let (failure, receiver) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let origin = format!("http://{address}");
            let request = Request::builder()
                .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let client = Client::builder(TokioExecutor::new()).build_http();
            execute_with_feedback(
                &client,
                &origin,
                request,
                &close_program(),
                Duration::from_secs(1),
                Some(receiver).into(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), cleanup_started)
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !task.is_finished(),
            "flushing the client's close cannot release a still-closing session"
        );
        if reject {
            failure.send(true).unwrap();
            let response = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                response.observation.end.reason,
                EndReason::DependencyFailure
            );
            assert!(!response.observation.end.clean);
            // The peer is still blocked: rejection did not wait for its loop.
            release.send(()).unwrap();
        } else {
            release.send(()).unwrap();
            let response = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(response.observation.end.clean);
            assert_eq!(response.observation.end.reason, EndReason::ClientClose);
            assert!(
                response.observation.end.offset_ms < 1000,
                "bounded peer cleanup should complete"
            );
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn peer_close_wait_uses_its_own_cleanup_budget_and_reports_incomplete_cleanup() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release, blocked) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text("40{\"sid\":\"live\"}".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "41"
        );
        blocked.await.unwrap();
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let mut input = close_program();
    input.policy.request_timeout_ms = 150;
    input.policy.cleanup_timeout_ms = 500;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        execute(&client, &origin, request, &input, Duration::from_secs(1)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!response.observation.end.clean);
    assert_eq!(response.observation.end.reason, EndReason::CleanupTimeout);
    assert!(
        response.observation.end.offset_ms >= 450,
        "normal close has its own cleanup budget after primary completion"
    );
    release.send(()).unwrap();
    server.await.unwrap();
}
