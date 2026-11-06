//! Unproven gaps retain their clock; actual event/ACK bindings remain mandatory.
use super::*;

#[tokio::test]
async fn fast_heartbeat_tail_waits_for_real_ack_and_delivery_and_sends_no_close_frame() {
    use crate::interaction::replay::timing::{FastTail, InputTiming};
    use futures_util::future::BoxFuture;
    use std::sync::Arc;
    use tokio::sync::{Notify, oneshot};

    #[derive(Default)]
    struct Timing {
        reached: Notify,
        dependencies_delivered: Notify,
    }
    impl InputTiming for Timing {
        fn wait(&self, _: u64, _: Vec<u64>) -> BoxFuture<'_, Result<Advance>> {
            Box::pin(async { Ok(Advance::default()) })
        }
        fn fast_tail(&self) -> Option<FastTail> {
            Some(FastTail {
                close_sequence: None,
                output_count: 3,
                idle_ms: 5,
                heartbeat_acks: Some([2].into()),
            })
        }
        fn wait_fast_tail(&self) -> BoxFuture<'_, Result<Advance>> {
            Box::pin(async {
                self.reached.notify_one();
                self.dependencies_delivered.notified().await;
                Ok(Advance::default())
            })
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (input_received, received) = oneshot::channel();
    let (send_ack, wait_ack) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text(r#"40{"sid":"live"}"#.into()))
            .await
            .unwrap();
        assert!(
            socket
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap()
                .starts_with("421")
        );
        input_received.send(()).unwrap();
        wait_ack.await.unwrap();
        socket
            .send(Message::Text(r#"431["ok"]"#.into()))
            .await
            .unwrap();
        assert!(
            matches!(socket.next().await, None | Some(Err(_))),
            "the engine should release TCP without sending a WebSocket or Engine.IO frame"
        );
    });

    let mut input = program();
    input.policy.completion.clear();
    input.socket_io_heartbeat = Some(Default::default());
    let timing = Arc::new(Timing::default());
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let timing_client = timing.clone();
    let replay = tokio::spawn(async move {
        execute_with_feedback(
            &client,
            &origin,
            request,
            &input,
            Duration::from_secs(2),
            Feedback {
                input_timing: Some(timing_client),
                ..Feedback::default()
            },
        )
        .await
        .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        received.await.unwrap();
        assert!(!replay.is_finished());
        send_ack.send(()).unwrap();
        timing.reached.notified().await;
        assert!(!replay.is_finished());
        timing.dependencies_delivered.notify_one();
        let actual = replay.await.unwrap().observation;
        assert_eq!(actual.end.reason, EndReason::FastHeartbeatTailSkipped);
        assert!(actual.end.clean);
        assert!(actual.end.close.is_none());
        assert_eq!(actual.end.pending, vec![2]);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn legacy_unproven_gaps_keep_offsets_and_actual_ack_rebinding() {
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
    input.actions[1].offset_ms = 120;
    input.actions[1].ack_ref = Some(crate::interaction::model::AckReference {
        namespace: "/".into(),
        server_event_ordinal: 1,
    });
    input.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("43123[\"received\"]"),
    };
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 160,
        offset_us: None,
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
    assert!(response.observation.end.offset_ms >= 160);
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
            Some(receiver).into(),
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
async fn uncompressed_close_retains_missing_heartbeat_evidence() {
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
        offset_ms: 40,
        offset_us: None,
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
        offset_ms: 80,
        offset_us: None,
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
    assert!(!response.observation.end.clean);
    assert!(response.observation.end.offset_ms >= 80);
    server.await.unwrap();
}
