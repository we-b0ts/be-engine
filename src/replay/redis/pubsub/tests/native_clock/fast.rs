//! Real Redis and WebSocket I/O exercise the compressed prefix and recorded tail.
use super::*;
use crate::interaction::{model::EndReason, observation::Observation};
use futures_util::{SinkExt, StreamExt};
use tokio::time::{Instant, timeout};
use tokio_tungstenite::tungstenite::Message;

const OPEN: &str = r#"0{"sid":"engine","upgrades":[],"pingInterval":1000,"pingTimeout":500}"#;
const CONNECT: &str = "40/chat,{}";
const CONNECTED: &str = r#"40/chat,{"sid":"chat"}"#;

fn packet(n: u64) -> String {
    format!("42/chat,{}", json!(["notice", n]))
}

fn recording(root: &Path) -> (Value, Vec<Value>, Vec<Vec<u8>>) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    let mut source = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    source.output(WireMessage::text(OPEN), 0).unwrap();
    source.input(WireMessage::text(CONNECT), 1).unwrap();
    source.output(WireMessage::text(CONNECTED), 2).unwrap();
    source.output(WireMessage::text(packet(1)), 501).unwrap();
    source.output(WireMessage::text("2"), 1000).unwrap();
    source.input(WireMessage::text("3"), 1250).unwrap();
    source.output(WireMessage::text("2"), 2250).unwrap();
    source.output(WireMessage::text(packet(2)), 2701).unwrap();
    source.server_close(Some(1000), String::new());
    let (input, expected) = source.finish(EndReason::ServerEof, 2791, true).unwrap();
    let request = json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket",
        "timestamp":START,"headers":{},"body":capture(b""),"interaction":input});
    std::fs::write(root.join("case/request.json"), request.to_string()).unwrap();
    std::fs::write(
        root.join("case/expected-response.json"),
        json!({"status":101,"interaction":expected}).to_string(),
    )
    .unwrap();
    let subscriber = Uuid::new_v4();
    let mut dependencies = vec![exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], SUBSCRIBED)];
    let mut frames = Vec::new();
    for (i, timestamp) in [
        "2020-01-01T00:10:00.500Z",
        "2020-01-01T00:10:02.700Z",
        "2020-01-01T00:10:02.765Z",
    ]
    .into_iter()
    .enumerate()
    {
        let value = json!({"method":"emit","event":"notice","data":[i+1],"binary":false,
            "namespace":"/chat","room":"user:7","skip_sid":null,"callback":null,"host_id":SOURCE});
        let raw = crate::redis::encode_array(&[
            b"message",
            b"jobs",
            &serde_json::to_vec(&value).unwrap(),
        ]);
        let mut incoming = push(subscriber, None, &raw, 600_000);
        incoming["timestamp"] = timestamp.into();
        dependencies.push(incoming);
        frames.push(raw);
    }
    (request, dependencies, frames)
}

#[tokio::test]
async fn compressed_passive_prefix_observes_tail_without_sending_pong() {
    let temp = tempfile::tempdir().unwrap();
    let (request, globals, frames) = recording(temp.path());
    let runtime = super::recording::fast_runtime(temp.path(), &[], &globals)
        .await
        .unwrap();
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
        stream.set_nodelay(true).unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(OPEN.into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            CONNECT
        );
        let (mut subscriber, task) = connect(&target_runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        socket.send(Message::Text(CONNECTED.into())).await.unwrap();
        socket.send(Message::Text("2".into())).await.unwrap();
        for (i, frame) in frames.into_iter().enumerate() {
            assert_eq!(
                timeout(Duration::from_millis(200), read(&mut subscriber))
                    .await
                    .expect("tail input must not wait for the scheduled PONG"),
                frame
            );
            socket
                .send(Message::Text(packet(i as u64 + 1).into()))
                .await
                .unwrap();
        }
        tokio::select! {
            message = socket.next() => panic!("unexpected traffic during EOF grace: {message:?}"),
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
        socket.send(Message::Text(packet(4).into())).await.unwrap();
        assert!(matches!(socket.next().await, None | Some(Err(_))));
        task.abort();
    });
    let client = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        Duration::from_secs(2),
        1024 * 1024,
    )
    .with_input_registration(&session, CASE);
    let started = Instant::now();
    let output = timeout(
        Duration::from_secs(2),
        client.send_bytes(&serde_json::to_vec(&request).unwrap(), "fast-passive"),
    )
    .await
    .expect("the replay must close without waiting for the recorded heartbeat timeout")
    .unwrap()
    .interaction
    .unwrap();
    assert_eq!(output.end.reason, EndReason::FastHeartbeatTailSkipped);
    assert!(output.end.clean);
    let business: Vec<_> = output
        .events
        .iter()
        .filter(|event| !event.heartbeat)
        .collect();
    assert_eq!(
        business.len(),
        6,
        "retain extra output on both sides of the inferred EOF"
    );
    assert_eq!(business[4].message, WireMessage::text(packet(3)));
    assert_eq!(business[5].message, WireMessage::text(packet(4)));
    assert!(business[4].offset_ms >= business[3].offset_ms + 63);
    let eof = output.end.fast_heartbeat_eof_ms.unwrap();
    assert!(eof >= business[4].offset_ms + 15);
    assert!(business[5].offset_ms > eof);
    assert!((1000..1250).contains(&(output.end.offset_ms - eof)));
    assert!(started.elapsed() < Duration::from_secs(2));
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
        3
    );
}

#[tokio::test]
async fn ordered_fast_push_arrives_before_the_input_that_awaits_its_output() {
    let temp = tempfile::tempdir().unwrap();
    let (mut globals, frame) = fixture(temp.path());
    globals[1]["timestamp"] = "2020-01-01T00:10:20Z".into();
    let policy = InteractionPolicy {
        completion: ["join", "next"]
            .into_iter()
            .map(|event| crate::interaction::policy::EventCompletion {
                namespace: "/chat".into(),
                event: event.into(),
                completion: crate::interaction::policy::CompletionRule::Ack,
            })
            .collect(),
        ..InteractionPolicy::default()
    };
    let mut source = Observation::new(Protocol::SocketIo, policy).unwrap();
    let (first, second) = (r#"42/chat,0["join"]"#, r#"42/chat,1["next"]"#);
    let (ack, notice) = (
        "43/chat,0[true]",
        r#"42/chat,["example:notice",{"value":7}]"#,
    );
    source.output(WireMessage::text(OPEN), 0).unwrap();
    source.input(WireMessage::text(CONNECT), 1).unwrap();
    source.output(WireMessage::text(CONNECTED), 2).unwrap();
    source.input(WireMessage::text(first), 10).unwrap();
    source.output(WireMessage::text(ack), 20).unwrap();
    source.output(WireMessage::text(notice), 20_001).unwrap();
    source.input(WireMessage::text(second), 30_000).unwrap();
    source
        .output(WireMessage::text("43/chat,1[true]"), 30_001)
        .unwrap();
    let (input, expected) = source
        .finish(EndReason::BusinessIdle, 31_000, true)
        .unwrap();
    assert!(expected.end.clean);
    let request = json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket",
        "timestamp":START,"headers":{},"body":capture(b""),"interaction":input});
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    std::fs::write(
        temp.path().join("case/expected-response.json"),
        json!({"status":101,"interaction":expected}).to_string(),
    )
    .unwrap();

    let mut get = exchange(Uuid::new_v4(), 1, "GET", &[b"join"], b"+OK\r\n");
    get["request_started_at"] = "2020-01-01T00:10:00.100Z".into();
    get["timestamp"] = "2020-01-01T00:10:00.101Z".into();
    get["response_kind"] = "simple_string".into();
    let runtime = super::recording::fast_runtime(temp.path(), &[get], &globals)
        .await
        .unwrap();
    assert!(
        runtime
            .state
            .lock()
            .await
            .redis
            .pubsub
            .native_clock
            .needs_observer(CASE)
    );
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
    let target = tokio::spawn(async move {
        let (stream, _) = ws.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(OPEN.into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            CONNECT
        );
        let (mut subscriber, subscription) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        socket.send(Message::Text(CONNECTED.into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            first
        );
        guards::silent(&mut subscriber).await;
        socket.send(Message::Text(ack.into())).await.unwrap();
        guards::silent(&mut subscriber).await;
        let (mut redis, requests) = connect(&runtime).await;
        assert_eq!(send(&mut redis, &[b"GET", b"join"]).await, b"+OK\r\n");
        assert_eq!(read(&mut subscriber).await, frame);
        socket.send(Message::Text(notice.into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            second
        );
        socket
            .send(Message::Text("43/chat,1[true]".into()))
            .await
            .unwrap();
        socket.close(None).await.unwrap();
        requests.abort();
        subscription.abort();
    });
    let client = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        Duration::from_secs(2),
        1024 * 1024,
    )
    .with_input_registration(&session, CASE);
    let output = timeout(
        Duration::from_secs(2),
        client.send(&temp.path().join("case/request.json")),
    )
    .await
    .expect("the push must not wait for the input that requires its output")
    .unwrap()
    .interaction
    .unwrap();
    target.await.unwrap();
    assert!(output.end.clean);
    assert!(output.end.missing_predecessor.is_none());
    control.abort();
}
