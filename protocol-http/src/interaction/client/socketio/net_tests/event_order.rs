use super::*;
use crate::interaction::client::{
    event_order::{Checkpoint, EventKey, Order},
    timing::InputTiming,
};

struct Fast;

impl InputTiming for Fast {
    fn wait(&self, _: u64, _: Vec<u64>) -> futures_util::future::BoxFuture<'_, Result<Advance>> {
        Box::pin(async { Ok(Advance::default()) })
    }

    fn ordered_fast(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn fast_namespace_disconnect_waits_for_the_recorded_ack_prefix() {
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
            .send(Message::Text(r#"40{"sid":"live"}"#.into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            r#"421["ask",{"value":7}]"#
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.next())
                .await
                .is_err()
        );
        socket
            .send(Message::Text("431[true]".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "41"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
    });
    let mut input = program();
    let mut close = input.actions[0].clone();
    close.sequence = 3;
    close.offset_ms = 20;
    close.action = InputActionKind::Message {
        message: WireMessage::text("41"),
    };
    input.actions.push(close.clone());
    close.sequence = 4;
    close.offset_ms = 25;
    close.action = InputActionKind::Message {
        message: WireMessage::text("1"),
    };
    input.actions.push(close);
    let order = Order::new(vec![(
        EventKey::Ack("/".into(), 1),
        Checkpoint {
            sequence: 3,
            offset_ms: 10,
        },
    )]);
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = tokio::time::timeout(
        Duration::from_secs(2),
        execute_with_feedback(
            &client,
            &origin,
            request,
            &input,
            Duration::from_secs(1),
            Feedback {
                input_timing: Some(std::sync::Arc::new(Fast)),
                event_order: Some(order),
                ..Feedback::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .observation;
    assert_eq!(actual.end.reason, EndReason::ClientClose);
    assert!(actual.end.clean);
    server.await.unwrap();
}

#[tokio::test]
async fn missing_event_ends_the_session_without_sending_the_blocked_input() {
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
            .send(Message::Text(r#"40{"sid":"live"}"#.into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            r#"421["ask",{"value":7}]"#
        );
        let sent_at = Instant::now();
        assert!(matches!(socket.next().await, None | Some(Err(_))));
        assert!(sent_at.elapsed() >= Duration::from_millis(4_990));
    });
    let mut input = program();
    input.policy.request_timeout_ms = 40_000;
    input.policy.max_duration_ms = 40_000;
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 30_000,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text(r#"42["next"]"#),
        },
    });
    let mut close = input.actions.last().unwrap().clone();
    close.sequence = 4;
    close.offset_ms = 30_080;
    close.action = InputActionKind::Message {
        message: WireMessage::text("1"),
    };
    input.actions.push(close);
    let order = Order::new(vec![(
        EventKey::Ack("/".into(), 1),
        Checkpoint {
            sequence: 3,
            offset_ms: 20,
        },
    )]);
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = tokio::time::timeout(
        Duration::from_secs(7),
        execute_with_feedback(
            &client,
            &origin,
            request,
            &input,
            Duration::from_secs(1),
            Feedback {
                input_timing: Some(std::sync::Arc::new(Fast)),
                event_order: Some(order),
                ..Feedback::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap()
    .observation;
    assert_eq!(actual.end.reason, EndReason::MissingPredecessor);
    assert_eq!(
        actual.end.missing_predecessor,
        Some(crate::interaction::model::MissingPredecessor {
            input_sequence: 3,
            output_sequence: 3,
        })
    );
    assert!(actual.end.offset_ms >= 5_000 && actual.end.offset_ms < 6_000);
    assert_eq!(
        actual.end.dispatch_timeout.unwrap().stage,
        DispatchStage::Prerequisites
    );
    assert!(!actual.end.clean);
    server.await.unwrap();
}
