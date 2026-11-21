use super::*;

fn source_program() -> InputTranscript {
    let mut source = Observation::new(Protocol::SocketIo, policy()).unwrap();
    source.output(WireMessage::text(open()), 0).unwrap();
    source.input(WireMessage::text("40"), 0).unwrap();
    source
        .output(WireMessage::text(r#"40{"sid":"source-ns"}"#), 0)
        .unwrap();
    source
        .input(WireMessage::text(r#"421["ask",{"value":7}]"#), 1)
        .unwrap();
    source.output(WireMessage::text(r#"431["ok"]"#), 2).unwrap();
    source
        .input(WireMessage::text(r#"422["ask",{"value":8}]"#), 3)
        .unwrap();
    source
        .output(WireMessage::text("2source-payload"), 4)
        .unwrap();
    source
        .input(WireMessage::text("3source-payload"), 8)
        .unwrap();
    source.output(WireMessage::text(r#"432["ok"]"#), 9).unwrap();
    source.server_close(Some(1000), String::new());
    let (program, output) = source.finish(EndReason::ServerEof, 12, true).unwrap();
    assert!(output.end.clean);
    assert_eq!(program.actions[2].after, vec![2]);
    program
}

#[tokio::test]
async fn recorded_pong_does_not_wait_for_a_later_business_completion_barrier() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text(r#"40{"sid":"target-ns"}"#.into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            r#"421["ask",{"value":7}]"#
        );
        socket
            .send(Message::Text("2actual-target-payload".into()))
            .await
            .unwrap();
        let pong = tokio::time::timeout(Duration::from_millis(80), socket.next())
            .await
            .expect("protocol response must not wait for the withheld business ACK")
            .unwrap()
            .unwrap();
        assert_eq!(pong.into_text().unwrap(), "3actual-target-payload");
        socket
            .send(Message::Text(r#"431["ok"]"#.into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            r#"422["ask",{"value":8}]"#
        );
        socket
            .send(Message::Text(r#"432["ok"]"#.into()))
            .await
            .unwrap();
        socket
            .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: 1000.into(),
                reason: "".into(),
            }))
            .await
            .unwrap();
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = execute(
        &client,
        &origin,
        request,
        &source_program(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(actual.observation.end.clean);
    assert_eq!(actual.observation.end.reason, EndReason::ServerEof);
    peer.await.unwrap();
}

#[tokio::test]
async fn target_close_cannot_certify_a_recorded_heartbeat_response_that_was_never_possible() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text(r#"40{"sid":"target-ns"}"#.into()))
            .await
            .unwrap();
        socket.next().await.unwrap().unwrap();
        socket
            .send(Message::Text(r#"431["ok"]"#.into()))
            .await
            .unwrap();
        socket.next().await.unwrap().unwrap();
        socket
            .send(Message::Text(r#"432["ok"]"#.into()))
            .await
            .unwrap();
        // No Target PING exists to authorize the recorded client PONG.
        socket
            .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: 1000.into(),
                reason: "".into(),
            }))
            .await
            .unwrap();
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let actual = execute(
        &client,
        &origin,
        request,
        &source_program(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(!actual.observation.end.clean);
    peer.await.unwrap();
}
