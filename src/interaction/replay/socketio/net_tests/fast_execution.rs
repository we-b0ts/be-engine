//! Unproven gaps retain their clock; actual event/ACK bindings remain mandatory.
use super::*;

#[tokio::test]
async fn terminal_ping_gets_a_pong_only_after_a_new_business_frame() {
    assert_target_times_out_after_terminal_ping(true).await;
}

#[tokio::test]
async fn terminal_ping_allows_target_timeout_despite_missing_output_and_dependency_failure() {
    assert_target_times_out_after_terminal_ping(false).await;
}

async fn assert_target_times_out_after_terminal_ping(business_output: bool) {
    use crate::interaction::replay::timing::{FastTail, InputTiming};
    use futures_util::future::BoxFuture;
    use std::sync::Arc;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};

    struct Timing;
    impl InputTiming for Timing {
        fn wait(&self, _: u64, _: Vec<u64>) -> BoxFuture<'_, Result<Advance>> {
            Box::pin(async { Ok(Advance::default()) })
        }
        fn fast_tail(&self) -> Option<FastTail> {
            Some(FastTail {
                close_sequence: None,
                output_count: 3,
                idle_ms: 5,
                heartbeat_timeout: true,
                native_observation: false,
            })
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (failed, failure) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                r#"0{"sid":"target","pingInterval":1000,"pingTimeout":100}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        // The final input has not been sent. Ordinary pings still get a pong.
        socket.send(Message::Text("2".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "3"
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

        if business_output {
            socket.send(Message::Text("2".into())).await.unwrap();
            assert!(
                timeout(Duration::from_millis(15), socket.next())
                    .await
                    .is_err()
            );
            socket
                .send(Message::Text(r#"431["ok"]"#.into()))
                .await
                .unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "3"
            );
        } else {
            // Deliberately leave the final ACK missing and signal a dependency failure.
            let _ = failed.send(true);
        }
        socket.send(Message::Text("2".into())).await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), socket.next())
                .await
                .is_err()
        );
        socket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })))
            .await
            .unwrap();
    });

    let mut input = program();
    input.policy.business_idle_ms = 30;
    input.policy.request_timeout_ms = 50;
    input.socket_io_heartbeat = Some(Default::default());
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = timeout(
        Duration::from_secs(2),
        execute_with_feedback(
            &client,
            &origin,
            request,
            &input,
            Duration::from_secs(2),
            Feedback {
                input_timing: Some(Arc::new(Timing)),
                dependency_failure: Some(failure),
                ..Feedback::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .observation;
    assert_eq!(actual.end.reason, EndReason::ServerEof);
    assert_eq!(actual.end.close.unwrap().code, Some(1000));
    assert!(actual.end.clean);
    assert!(actual.end.fast_heartbeat_eof_ms.is_some());
    assert_eq!(
        actual.end.pending,
        if business_output { vec![] } else { vec![2] }
    );
    server.await.unwrap();
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
