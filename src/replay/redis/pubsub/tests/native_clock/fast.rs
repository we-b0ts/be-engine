//! Real Redis and WebSocket I/O exercise the compressed prefix and recorded tail.
use super::*;
use crate::interaction::{model::EndReason, observation::Observation};
use futures_util::{SinkExt, StreamExt};
use tokio::time::{Instant, timeout};
use tokio_tungstenite::tungstenite::Message;

const OPEN: &str = r#"0{"sid":"engine","upgrades":[],"pingInterval":1000,"pingTimeout":500}"#;
const CONNECT: &str = "40/chat,{}";
const CONNECTED: &str = r#"40/chat,{"sid":"chat"}"#;
const JOIN: &str = r#"42/chat,0["join"]"#;
const JOINED: &str = "43/chat,0[true]";

fn packet(n: u64) -> String {
    format!("42/chat,{}", json!(["notice", n]))
}

type Deliveries = Vec<(Vec<u8>, Option<u64>)>;

fn recording(root: &Path, setup: bool) -> (Value, Vec<Value>, Deliveries) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    let mut source = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    source.output(WireMessage::text(OPEN), 0).unwrap();
    source.input(WireMessage::text(CONNECT), 1).unwrap();
    source.output(WireMessage::text(CONNECTED), 2).unwrap();
    if setup {
        source.input(WireMessage::text(JOIN), 10).unwrap();
        source.output(WireMessage::text(JOINED), 20).unwrap();
    }
    let second = if setup { 1 } else { 2 };
    source.output(WireMessage::text(packet(1)), 501).unwrap();
    source.output(WireMessage::text("2"), 1000).unwrap();
    source.input(WireMessage::text("3"), 1250).unwrap();
    source.output(WireMessage::text("2"), 2250).unwrap();
    source
        .output(WireMessage::text(packet(second)), 2701)
        .unwrap();
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
    let mut deliveries = vec![
        ("2020-01-01T00:10:00.500Z", 1, "user:7", Some(1)),
        ("2020-01-01T00:10:02.700Z", second, "user:7", Some(second)),
        ("2020-01-01T00:10:02.765Z", 3, "user:7", Some(3)),
    ];
    if setup {
        deliveries.insert(1, ("2020-01-01T00:10:00.504Z", 1, "mirror:7", None));
        deliveries.insert(3, ("2020-01-01T00:10:02.704Z", 1, "mirror:7", None));
    }
    for (timestamp, value, room, output) in deliveries {
        let value = json!({"method":"emit","event":"notice","data":[value],"binary":false,
            "namespace":"/chat","room":room,"skip_sid":null,"callback":null,"host_id":SOURCE});
        let raw = crate::redis::encode_array(&[
            b"message",
            b"jobs",
            &serde_json::to_vec(&value).unwrap(),
        ]);
        let mut incoming = push(subscriber, None, &raw, 600_000);
        incoming["timestamp"] = timestamp.into();
        dependencies.push(incoming);
        frames.push((raw, output));
    }
    (request, dependencies, frames)
}

#[tokio::test]
async fn compressed_passive_prefix_answers_pings_only_when_output_continues() {
    replay_passive_prefix(false).await;
}

#[tokio::test]
async fn compressed_passive_prefix_preserves_identical_pushes_after_live_join_ack() {
    replay_passive_prefix(true).await;
}

async fn replay_passive_prefix(setup: bool) {
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};

    let temp = tempfile::tempdir().unwrap();
    let (request, globals, frames) = recording(temp.path(), setup);
    let delivery_count = frames.len();
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
        if setup {
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                JOIN
            );
            guards::silent(&mut subscriber).await;
            socket.send(Message::Text(JOINED.into())).await.unwrap();
        }
        socket.send(Message::Text("2".into())).await.unwrap();
        for (i, (frame, output)) in frames.into_iter().enumerate() {
            assert_eq!(
                timeout(Duration::from_millis(200), read(&mut subscriber))
                    .await
                    .expect("native output must continue during heartbeat observation"),
                frame
            );
            if let Some(value) = output {
                socket
                    .send(Message::Text(packet(value).into()))
                    .await
                    .unwrap();
            }
            if i == 0 {
                assert_eq!(
                    socket.next().await.unwrap().unwrap().into_text().unwrap(),
                    "3"
                );
            }
        }
        socket.send(Message::Text("2".into())).await.unwrap();
        assert!(
            timeout(Duration::from_millis(30), socket.next())
                .await
                .is_err()
        );
        socket.send(Message::Text(packet(4).into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "3"
        );
        socket.send(Message::Text("2".into())).await.unwrap();
        assert!(
            timeout(Duration::from_millis(500), socket.next())
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
    .expect("the replay must observe the actual Target heartbeat timeout")
    .unwrap()
    .interaction
    .unwrap();
    assert_eq!(output.end.reason, EndReason::ServerEof);
    assert!(output.end.clean);
    let business: Vec<_> = output
        .events
        .iter()
        .filter(|event| !event.heartbeat)
        .collect();
    let extra_index = if setup { 5 } else { 4 };
    assert_eq!(
        business.len(),
        extra_index + 2,
        "retain extra output before the actual EOF"
    );
    if setup {
        assert_eq!(business[2].message, WireMessage::text(JOINED));
        assert_eq!(business[3].message, WireMessage::text(packet(1)));
        assert_eq!(business[4].message, WireMessage::text(packet(1)));
    }
    assert_eq!(business[extra_index].message, WireMessage::text(packet(3)));
    assert_eq!(
        business[extra_index + 1].message,
        WireMessage::text(packet(4))
    );
    assert!(business[extra_index].offset_ms >= business[extra_index - 1].offset_ms + 63);
    let eof = output.end.fast_heartbeat_eof_ms.unwrap();
    assert!(eof >= business[extra_index + 1].offset_ms + 490);
    assert!(output.end.offset_ms.saturating_sub(eof) <= 1);
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
        delivery_count
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

#[tokio::test]
async fn namespace_disconnect_opens_fast_window_for_earlier_native_push() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    let mut source = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    source.output(WireMessage::text(OPEN), 0).unwrap();
    source.input(WireMessage::text(CONNECT), 1).unwrap();
    source.output(WireMessage::text(CONNECTED), 2).unwrap();
    source.input(WireMessage::text(JOIN), 10).unwrap();
    source.output(WireMessage::text(JOINED), 20).unwrap();
    source.output(WireMessage::text(packet(1)), 11_001).unwrap();
    source.input(WireMessage::text("41/chat,"), 30_000).unwrap();
    source.client_close(None, String::new(), 30_001).unwrap();
    let (input, expected) = source.finish(EndReason::ClientClose, 30_002, true).unwrap();
    let request = json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket",
        "timestamp":START,"headers":{},"body":capture(b""),"interaction":input});
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    std::fs::write(
        temp.path().join("case/expected-response.json"),
        json!({"status":101,"interaction":expected}).to_string(),
    )
    .unwrap();
    let subscriber = Uuid::new_v4();
    let value = json!({"method":"emit","event":"notice","data":[1],"binary":false,
        "namespace":"/chat","room":"user:7","skip_sid":null,"callback":null,"host_id":SOURCE});
    let raw =
        crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(&value).unwrap()]);
    let mut incoming = push(subscriber, None, &raw, 600_000);
    incoming["timestamp"] = "2020-01-01T00:10:11.000Z".into();
    let globals = [
        exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], SUBSCRIBED),
        incoming,
    ];
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
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            JOIN
        );
        socket.send(Message::Text(JOINED.into())).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), read(&mut subscriber))
                .await
                .unwrap(),
            raw
        );
        assert!(
            timeout(Duration::from_millis(30), socket.next())
                .await
                .is_err()
        );
        socket.send(Message::Text(packet(1).into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "41/chat,"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        task.abort();
    });
    let client = crate::recorded_request::RecordedHttpClient::new(
        format!("http://{address}"),
        Duration::from_secs(2),
        1024 * 1024,
    )
    .with_input_registration(&session, CASE);
    let actual = timeout(
        Duration::from_secs(2),
        client.send(&temp.path().join("case/request.json")),
    )
    .await
    .unwrap()
    .unwrap()
    .interaction
    .unwrap();
    assert_eq!(actual.end.reason, EndReason::ClientClose);
    assert!(actual.end.clean);
    target.await.unwrap();
    control.abort();
}
