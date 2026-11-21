//! Namespace authentication must finish before compressed business inputs arrive.
use super::*;

#[derive(Default)]
struct NamespaceReceipts(std::sync::Mutex<Vec<(String, Option<String>)>>);

impl crate::interaction::client::NativeEventSink for NamespaceReceipts {
    fn observe(&self, _: NativeEvent) -> futures_util::future::BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn connected<'a>(
        &'a self,
        namespace: &'a str,
        sid: Option<&'a str>,
    ) -> futures_util::future::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap()
                .push((namespace.into(), sid.map(str::to_owned)));
            Ok(())
        })
    }
}

#[tokio::test]
async fn compressed_inputs_wait_for_actual_namespace_admission_without_recorded_barriers() {
    delayed_admission(false).await;
}

#[tokio::test]
async fn preserved_inputs_wait_for_actual_namespace_admission_without_recorded_barriers() {
    delayed_admission(true).await;
}

async fn delayed_admission(preserve_input_timing: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40/local-executor,{}"
        );
        // Model asynchronous native namespace authentication, rather than
        // reading the next packet only after writing an immediate CONNECT.
        let premature = tokio::time::timeout(Duration::from_millis(30), socket.next())
            .await
            .ok();
        let arrived_before_admission = premature.is_some();
        socket
            .send(Message::Text(
                "40/local-executor,{\"sid\":\"actual-namespace\"}".into(),
            ))
            .await
            .unwrap();
        let event = match premature {
            Some(event) => event,
            None => socket.next().await,
        };
        assert_eq!(
            event.unwrap().unwrap().into_text().unwrap(),
            "42/local-executor,201[\"device:register\",{}]"
        );
        socket
            .send(Message::Text("43/local-executor,201[\"ok\"]".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "41/local-executor,"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        arrived_before_admission
    });
    let mut input = program();
    input.policy.preserve_input_timing = preserve_input_timing;
    input.policy.completion.clear();
    input.actions.clear();
    for (index, packet) in [
        "40/local-executor,{}",
        "42/local-executor,201[\"device:register\",{}]",
        "41/local-executor,",
        "1",
    ]
    .into_iter()
    .enumerate()
    {
        input.actions.push(InputAction {
            sequence: index as u64 + 1,
            // The independent cancellation deadline must leave room for this
            // test's deliberately slower Target namespace authentication.
            offset_ms: [0, 1, 60, 100][index],
            offset_us: None,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text(packet),
            },
        });
    }
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let receipts = std::sync::Arc::new(NamespaceReceipts::default());
    let response = execute_with_feedback(
        &client,
        &origin,
        request,
        &input,
        Duration::from_secs(1),
        Feedback {
            native_events: Some(receipts.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        *receipts.0.lock().unwrap(),
        vec![("/local-executor".into(), Some("actual-namespace".into()))]
    );
    assert!(response.observation.end.clean);
    assert!(
        !server.await.unwrap(),
        "business event reached Target before its namespace admission completed"
    );
}

#[tokio::test]
async fn rejected_namespace_retains_actual_error_without_sending_business_inputs() {
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
            .send(Message::Text("44{\"message\":\"denied\"}".into()))
            .await
            .unwrap();
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
    input.actions[1].after.clear();
    input.actions[1].compressible_gap = false;
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(&client, &origin, request, &input, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(!response.observation.end.clean);
    assert!(
        response
            .observation
            .events
            .iter()
            .any(|event| event.message.data == "44{\"message\":\"denied\"}")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn explicit_client_cancellation_remains_available_during_namespace_admission() {
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
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });
    let mut input = program();
    input.actions[1].after.clear();
    input.actions[1].compressible_gap = false;
    input.actions[1].gap_start_ms = None;
    input.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("1"),
    };
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(&client, &origin, request, &input, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(response.observation.end.reason, EndReason::ClientClose);
    assert!(response.observation.end.clean);
    server.await.unwrap();
}

#[tokio::test]
async fn actual_server_event_ack_remains_available_during_namespace_admission() {
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
            .send(Message::Text("4277[\"setup\"]".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "4377[]"
        );
        socket
            .send(Message::Text("40{\"sid\":\"actual-namespace\"}".into()))
            .await
            .unwrap();
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
    input.actions[1].after.clear();
    input.actions[1].compressible_gap = false;
    input.actions[1].ack_ref = Some(crate::interaction::model::AckReference {
        namespace: "/".into(),
        server_event_ordinal: 1,
    });
    input.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("43123[]"),
    };
    input.actions.push(InputAction {
        sequence: 3,
        offset_ms: 6,
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
    let response = execute(&client, &origin, request, &input, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(response.observation.end.reason, EndReason::ClientClose);
    assert!(response.observation.end.clean);
    server.await.unwrap();
}
