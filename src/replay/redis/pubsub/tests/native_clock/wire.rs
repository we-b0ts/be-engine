//! The production private observer learns CONNECT from an actual WebSocket.
use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn slow_native_namespace_admission_precedes_real_redis_input_and_ws_output() {
    let temp = tempfile::tempdir().unwrap();
    let (globals, original) = fixture(temp.path());
    let path = temp.path().join("case/request.json");
    let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    request["uri"] = "/socket.io/?EIO=4&transport=websocket".into();
    request["headers"] = json!({});
    request["body"] = capture(b"");
    request["interaction"]["policy"]["business_idle_ms"] = 150.into();
    request["interaction"]["policy"]["input_gap_ms"] = 10.into();
    std::fs::write(path, request.to_string()).unwrap();
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let socket_path = temp.path().join("control.sock");
    let session = temp.path().join("session.json");
    std::fs::write(&session, json!({"control_socket":socket_path}).to_string()).unwrap();
    let listener = tokio::net::UnixListener::bind(socket_path).unwrap();
    let state = runtime.state.clone();
    let control = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            crate::replay::control::handle_control_stream(stream, state.clone(), None, None)
                .await
                .unwrap();
        }
    });
    assert_eq!(
        guards::control(&runtime, json!({"command":"request_begin","case_id":CASE})).await["ok"],
        true
    );
    let ws = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = ws.local_addr().unwrap();
    let target_runtime = runtime.clone();
    let target = tokio::spawn(async move {
        let (stream, _) = ws.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text("0{\"sid\":\"engine-sid\",\"upgrades\":[],\"pingInterval\":10000,\"pingTimeout\":10000}".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40/chat,{}"
        );
        let (mut subscriber, task) = connect(&target_runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(80), read_redis_frame(&mut subscriber))
                .await
                .is_err()
        );
        socket
            .send(Message::Text("40/chat,{\"sid\":\"live-chat-sid\"}".into()))
            .await
            .unwrap();
        let received = read(&mut subscriber).await;
        assert_eq!(received, original);
        let frame = parse_pubsub_push(&received).unwrap().unwrap();
        let data: Value = serde_json::from_slice(&frame.payload).unwrap();
        let packet = json!([data["event"], data["data"][0]]);
        socket
            .send(Message::Text(format!("42/chat,{packet}").into()))
            .await
            .unwrap();
        while let Some(message) = socket.next().await {
            if matches!(message.unwrap(), Message::Close(_)) {
                break;
            }
        }
        task.abort();
    });
    let client = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        Duration::from_secs(3),
        1024 * 1024,
    )
    .with_input_registration(&session, CASE);
    let response = client
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "native-clock")
        .await
        .unwrap();
    let output = response.interaction.unwrap();
    assert!(output.end.clean);
    assert_eq!(output.events.len(), 3);
    assert!(
        serde_json::to_string(&output)
            .unwrap()
            .contains("example:notice")
    );
    assert!(
        !serde_json::to_string(&output)
            .unwrap()
            .contains("NEVER_EXECUTE_EXPECTED")
    );
    target.await.unwrap();
    control.abort();
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .redis
            .pubsub
            .report()
            .unwrap()
            .delivered_pushes,
        1
    );
}
