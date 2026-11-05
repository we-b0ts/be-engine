//! Fast native replay may receive independent request ACKs in either order.
use super::*;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::Request;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn open(sid: &str) -> String {
    format!(
        r#"0{{"sid":"{sid}","upgrades":[],"pingInterval":10000,"pingTimeout":10000,"maxPayload":1048576}}"#
    )
}

#[tokio::test]
async fn actual_reversed_acks_keep_payload_ownership_with_overlapping_inputs() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(open("target").into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40/n,"
        );
        socket
            .send(Message::Text(r#"40/n,{"sid":"target-ns"}"#.into()))
            .await
            .unwrap();
        for id in [936, 811] {
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                format!("42/n,{id}[\"heartbeat\",{{}}]")
            );
        }
        // Both original inputs are in flight; the client library matches by id.
        socket.send(Message::Text(B.into())).await.unwrap();
        socket.send(Message::Text(A.into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "41/n,"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });
    let mut program = input();
    program.policy.business_idle_ms = 500;
    program.policy.request_timeout_ms = 1500;
    program.policy.max_duration_ms = 2000;
    program.policy.cleanup_timeout_ms = 200;
    program.policy.completion = vec![crate::interaction::policy::EventCompletion {
        namespace: "/n".into(),
        event: "heartbeat".into(),
        completion: crate::interaction::policy::CompletionRule::Ack,
    }];
    for action in &mut program.actions {
        action.sequence += 1;
        action.after = vec![1];
        action.offset_ms /= 1000;
    }
    program.actions.insert(
        0,
        InputAction {
            sequence: 1,
            offset_ms: 0,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text("40/n,"),
            },
        },
    );
    for (sequence, offset_ms, message) in [(4, 143, "41/n,"), (5, 187, "1")] {
        program.actions.push(InputAction {
            sequence,
            offset_ms,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text(message),
            },
        });
    }
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let started = std::time::Instant::now();
    let actual = crate::interaction::replay::execute(
        &client,
        &origin,
        request,
        &program,
        std::time::Duration::from_millis(1500),
        1024 * 1024,
        Default::default(),
    )
    .await
    .unwrap()
    .observation;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "overlapping requests must not be serialized waiting for the first ACK"
    );
    assert!(actual.end.clean);
    let source = output(&[&open("source"), r#"40/n,{"sid":"source-ns"}"#, A, B]);
    assert!(
        !super::super::super::compare_outputs_global(
            Some(&source),
            Some(&actual),
            None,
            Default::default(),
            Default::default()
        )
        .unwrap()
        .passed()
    );
    let context = Context::prepare(Some(&program)).unwrap().unwrap();
    let checked = super::super::super::compare_outputs_global_with_time_copies(
        Some(&source),
        Some(&actual),
        None,
        Default::default(),
        Default::default(),
        &Default::default(),
        Some(&context),
        false,
    )
    .unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    server.await.unwrap();
}
