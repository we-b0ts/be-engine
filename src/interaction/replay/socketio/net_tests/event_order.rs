use super::*;
use crate::interaction::replay::event_order::{Checkpoint, EventKey, Order};

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
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
    });
    let mut input = program();
    input.policy.request_timeout_ms = 9_000;
    input.policy.max_duration_ms = 9_000;
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 50,
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
    close.offset_ms = 80;
    close.action = InputActionKind::Message {
        message: WireMessage::text("1"),
    };
    input.actions.push(close);
    let order = Order::new(
        vec![(
            EventKey::Ack("/".into(), 1),
            Checkpoint {
                sequence: 3,
                offset_ms: 20,
            },
        )],
        true,
    );
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
    assert!(actual.end.offset_ms >= 5_050);
    assert!(!actual.end.clean);
    server.await.unwrap();
}
