//! Client idle offsets are optional; actual event/ACK dependencies are not.
use super::*;

#[tokio::test]
async fn socketio_compresses_legacy_idle_offsets_and_keeps_actual_ack_rebinding() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
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
        tokio::time::sleep(Duration::from_millis(30)).await;
        socket
            .send(Message::Text("42777[\"notice\",{}]".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "43777[\"received\"]"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
    });
    let mut input = program();
    input.actions[1].after.clear();
    input.actions[1].compressible_gap = false;
    input.actions[1].gap_start_ms = None;
    input.actions[1].offset_ms = 30_000;
    input.actions[1].ack_ref = Some(crate::interaction::model::AckReference {
        namespace: "/".into(),
        server_event_ordinal: 1,
    });
    input.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("43123[\"received\"]"),
    };
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 40_000,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("1"),
        },
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        execute(&client, &origin, request, &input, Duration::from_secs(1)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.observation.end.clean);
    assert!(response.observation.end.offset_ms >= 30);
    assert!(response.observation.end.offset_ms < 1000);
    server.await.unwrap();
}

#[tokio::test]
async fn dependency_rejection_ends_a_blocked_ack_without_synthesizing_output() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (failure, receiver) = tokio::sync::watch::channel(false);
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
        tokio::time::sleep(Duration::from_millis(30)).await;
        failure.send(true).unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });
    let mut input = program();
    input.policy.max_duration_ms = 900_000;
    input.policy.request_timeout_ms = 900_000;
    input.actions[1].after.clear();
    input.actions[1].compressible_gap = false;
    input.actions[1].gap_start_ms = None;
    input.actions[1].ack_ref = Some(crate::interaction::model::AckReference {
        namespace: "/".into(),
        server_event_ordinal: 1,
    });
    input.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("43123[\"received\"]"),
    };
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        execute_with_feedback(
            &client,
            &origin,
            request,
            &input,
            Duration::from_secs(1),
            Some(receiver),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status, hyper::StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response.observation.end.reason,
        EndReason::DependencyFailure
    );
    assert!(!response.observation.end.clean);
    assert_eq!(response.observation.events.len(), 2);
    server.await.unwrap();
}

#[tokio::test]
async fn fast_close_does_not_wait_for_a_recorded_heartbeat_ping_that_never_occurred() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
    });
    let mut input = program();
    input.actions.truncate(1);
    input.actions.push(InputAction {
        sequence: 2,
        offset_ms: 25_000,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("3"),
        },
    });
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 40_000,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("1"),
        },
    });
    input.socket_io_heartbeat = Some(crate::interaction::model::SocketIoHeartbeats {
        responses: vec![crate::interaction::model::HeartbeatResponse {
            input_sequence: 2,
            ping_ordinal: 1,
            delay_ms: 0,
        }],
    });
    let origin = format!("http://{address}");
    let client = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        execute(&client, &origin, request, &input, Duration::from_secs(1)),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.observation.end.clean);
    server.await.unwrap();
}
