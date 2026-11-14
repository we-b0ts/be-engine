//! Real WS + Redis input scheduling, with dependency completion and future-input fences.
use super::*;
use crate::interaction::model::{
    InputAction, InputActionKind, InputTranscript, Protocol, WireMessage,
};
use crate::interaction::policy::{CompletionRule, EventCompletion, InteractionPolicy};
use crate::interaction::replay::timing::SocketIoTiming;
use futures_util::{SinkExt, StreamExt};
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

const START: &str = "2020-01-01T00:00:00Z";
mod backpressure;
mod coalesced_delivery;
mod delivery_prefix;
mod ordered_fast;

fn action(sequence: u64, offset_ms: u64, data: &str) -> InputAction {
    InputAction {
        sequence,
        offset_ms,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text(data),
        },
    }
}

fn input(next_ms: u64) -> Value {
    let mut input = InputTranscript::new(
        Protocol::SocketIo,
        InteractionPolicy {
            business_idle_ms: 1000,
            cleanup_timeout_ms: 500,
            max_duration_ms: 60_000,
            request_timeout_ms: 60_000,
            input_gap_ms: 1,
            completion: vec![EventCompletion {
                namespace: "/".into(),
                event: "work".into(),
                completion: CompletionRule::Ack,
            }],
            ..Default::default()
        },
    );
    input.actions = vec![
        action(1, 0, "40"),
        action(2, 5, "421[\"work\"]"),
        action(3, next_ms, "422[\"work\"]"),
        action(4, next_ms + 40, "1"),
    ];
    input.actions[1].after = vec![1];
    input.actions[2].after = vec![2];
    input.actions[2].compressible_gap = true;
    input.actions[2].gap_start_ms = Some(200);
    json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket","timestamp":START,
        "headers":{},"body":capture(b""),"interaction":input})
}

async fn serve_control(
    root: &Path,
    runtime: &Arc<ReplayRuntime>,
) -> (PathBuf, tokio::task::JoinHandle<()>) {
    let socket_path = root.join("control.sock");
    let session = root.join("session.json");
    std::fs::write(&session, json!({"control_socket":socket_path}).to_string()).unwrap();
    let listener = tokio::net::UnixListener::bind(socket_path).unwrap();
    let state = runtime.state.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            crate::replay::control::handle_control_stream(stream, state.clone(), None, None)
                .await
                .unwrap();
        }
    });
    (session, task)
}

async fn text(socket: &mut tokio_tungstenite::WebSocketStream<TcpStream>) -> String {
    socket
        .next()
        .await
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn fast_input_waits_for_redis_delivery_but_never_for_its_own_future_get() {
    let temp = tempfile::tempdir().unwrap();
    let request = input(30_000);
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    let connection = Uuid::new_v4();
    let mut publish = exchange(connection, 1, "PUBLISH", &[b"jobs", b"first"], b":1\r\n");
    publish["timestamp"] = "2020-01-01T00:00:00.200Z".into();
    publish["request_started_at"] = "2020-01-01T00:00:00.080Z".into();
    publish["duration_ms"] = 120.into();
    let mut get = exchange(connection, 2, "GET", &[b"later"], b"+OK\r\n");
    get["response_kind"] = "simple_string".into();
    get["timestamp"] = "2020-01-01T00:00:30.002Z".into();
    get["request_started_at"] = "2020-01-01T00:00:30.001Z".into();
    let runtime = runtime(temp.path(), &[publish, get], &[], true)
        .await
        .unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target_runtime = runtime.clone();
    let target = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                "0{\"sid\":\"live\",\"upgrades\":[],\"pingInterval\":10000,\"pingTimeout\":10000}"
                    .into(),
            ))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "40");
        socket
            .send(Message::Text("40{\"sid\":\"ns\"}".into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "421[\"work\"]");
        let (mut redis, task) = connect(&target_runtime).await;
        redis
            .inner
            .write_all(&crate::redis::encode_array(&[
                b"PUBLISH", b"jobs", b"first",
            ]))
            .await
            .unwrap();
        // The WS ACK is earlier than the Redis response; matching alone must
        // not authorize the next input. Heartbeat replies stay live while gated.
        socket
            .send(Message::Text("431[\"done\"]".into()))
            .await
            .unwrap();
        socket.send(Message::Text("2live".into())).await.unwrap();
        assert_eq!(text(&mut socket).await, "3live");
        assert!(
            tokio::time::timeout(Duration::from_millis(70), socket.next())
                .await
                .is_err()
        );
        assert_eq!(read(&mut redis).await, b":1\r\n");
        assert_eq!(text(&mut socket).await, "422[\"work\"]");
        // GET is caused by this input. Including it in the previous prefix
        // would wait until the original 30-second deadline or deadlock.
        assert_eq!(send(&mut redis, &[b"GET", b"later"]).await, b"+OK\r\n");
        socket
            .send(Message::Text("432[\"done\"]".into()))
            .await
            .unwrap();
        let after = Instant::now();
        assert_eq!(text(&mut socket).await, "1");
        assert!(
            after.elapsed() >= Duration::from_millis(25),
            "close interval was incorrectly compressed"
        );
        socket.send(Message::Close(None)).await.unwrap();
        task.abort();
    });
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        crate::recorded_request::RecordedHttpClient::new(
            format!("http://{addr}"),
            Duration::from_secs(3),
            1024 * 1024,
        )
        .with_input_registration(&session, "case")
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "input-timing"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(result.interaction.unwrap().end.clean);
    assert!(started.elapsed() < Duration::from_secs(2));
    target.await.unwrap();
    control.abort();
}

#[tokio::test]
async fn recorded_mode_overrides_compression_without_changing_input_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let request = input(400);
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    let path = temp.path().join("case/request.json");
    std::fs::write(&path, request.to_string()).unwrap();
    let original = std::fs::read(&path).unwrap();
    let runtime = runtime(temp.path(), &[], &[], false).await.unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Recorded)
        .await
        .unwrap();
    let started = Instant::now();
    let advance = observer.wait(3, vec![2]).await.unwrap();
    assert_eq!(advance.removed_ms, 0);
    assert!(started.elapsed() >= Duration::from_millis(390));
    assert_eq!(std::fs::read(path).unwrap(), original);
    control.abort();
}

#[tokio::test]
async fn redis_response_delivery_is_distinct_from_a_later_rpc_callback() {
    let temp = tempfile::tempdir().unwrap();
    let program = input(30_000);
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), program.to_string()).unwrap();
    let subscriber_id = Uuid::new_v4();
    let publisher_id = Uuid::new_v4();
    let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let source_request = request(SOURCE, 1);
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
    let mut publish = exchange(
        publisher_id,
        1,
        "PUBLISH",
        &[b"jobs", &source_request],
        b":2\r\n",
    );
    publish["timestamp"] = "2020-01-01T00:00:00.180Z".into();
    let mut callback = push(subscriber_id, Some(publisher_id), &raw, 40_000);
    callback["timestamp"] = "2020-01-01T00:00:40Z".into();
    let runtime = runtime(
        temp.path(),
        &[publish, callback],
        &[exchange(
            subscriber_id,
            1,
            "SUBSCRIBE",
            &[b"jobs"],
            confirmed,
        )],
        false,
    )
    .await
    .unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    let (mut subscriber, sub_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        confirmed
    );
    let (mut publisher, pub_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut publisher, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
        b":2\r\n"
    );
    assert!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .redis
            .exchanges
            .iter()
            .any(|e| e.record.native.command == "PUBLISH"
                && e.status == ReplayExchangeStatus::Responding)
    );
    let advance = tokio::time::timeout(Duration::from_secs(1), observer.wait(3, vec![2]))
        .await
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_redis_frame(&mut subscriber))
            .await
            .is_err()
    );
    pub_task.abort();
    sub_task.abort();
    control.abort();
}

#[tokio::test]
async fn input_timing_rejects_stale_epochs_and_unknown_completion_ids() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(
        temp.path().join("case/request.json"),
        input(400).to_string(),
    )
    .unwrap();
    let runtime = runtime(temp.path(), &[], &[], false).await.unwrap();
    async fn control(runtime: &Arc<ReplayRuntime>, request: Value) -> Value {
        crate::replay::control::handle_control_request(
            serde_json::from_value(request).unwrap(),
            runtime.state.clone(),
            None,
            None,
        )
        .await
        .0
    }
    let begin = control(
        &runtime,
        json!({"command":"input_timing_begin","case_id":"case"}),
    )
    .await;
    assert_eq!(begin["ok"], true);
    for (epoch, completed) in [(json!(START), vec![2]), (begin["epoch"].clone(), vec![1])] {
        let reply = control(
            &runtime,
            json!({"command":"input_timing","case_id":"case",
            "input_timing":{"epoch":epoch,"sequence":3,"completed":completed}}),
        )
        .await;
        assert_eq!(reply["ok"], false);
    }
}
