//! Explicit transport cancellation is not trapped behind an unfinished ACK.
use super::*;

#[tokio::test]
async fn recorded_cancel_preempts_blocked_later_input_and_preserves_incomplete_evidence() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text("40{\"sid\":\"ns\"}".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "421[\"ask\",{\"value\":7}]"
        );
        let started = Instant::now();
        // No ACK: input 3 cannot start. Heartbeats still receive their actual reply.
        socket.send(Message::Text("2live".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "3live"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(started.elapsed() >= Duration::from_millis(90));
        socket.send(Message::Close(None)).await.unwrap();
    });
    let mut input = program();
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 80,
        after: vec![2],
        compressible_gap: true,
        gap_start_ms: Some(20),
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("422[\"ask\"]"),
        },
    });
    input.actions.push(InputAction {
        sequence: 4,
        offset_ms: 120,
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
    assert_eq!(response.observation.end.reason, EndReason::ClientClose);
    assert!(!response.observation.end.clean);
    assert!(response.observation.end.pending.contains(&2));
    target.await.unwrap();
}
