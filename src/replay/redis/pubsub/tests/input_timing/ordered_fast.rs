use super::*;
use crate::replay::ReplayStreamTiming;

async fn enable(runtime: &Arc<ReplayRuntime>) {
    let mut state = runtime.state.lock().await;
    state.stream_timing = Some(ReplayStreamTiming::Fast);
    state.stream_interval_cap_ms = 5;
}

fn recorded_exchange(
    connection: Uuid,
    sequence: u64,
    command: &str,
    args: &[&[u8]],
    response: &[u8],
    started: &str,
    completed: &str,
) -> Value {
    let mut record = exchange(connection, sequence, command, args, response);
    record["request_started_at"] = json!(started);
    record["timestamp"] = json!(completed);
    record
}

#[tokio::test]
async fn ordered_fast_replays_at_the_source_deadline_when_a_request_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let mut request = input(400);
    let actions = request["interaction"]["actions"].as_array_mut().unwrap();
    actions[2]["after"] = json!([]);
    actions[2]["compressible_gap"] = false.into();
    actions[2]["gap_start_ms"] = Value::Null;
    actions.insert(
        3,
        serde_json::to_value(action(4, 700, "423[\"work\"]")).unwrap(),
    );
    actions[4]["sequence"] = 5.into();
    actions[4]["offset_ms"] = 800.into();
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    let missing = json!({
        "event_type":"mysql_exchange", "connection_id":Uuid::new_v4(), "query_sequence":1,
        "target_host":"127.0.0.1", "target_port":3306, "database":"appdb", "username":"root",
        "request_started_at":"2020-01-01T00:00:00.500Z", "timestamp":"2020-01-01T00:00:00.501Z",
        "command":"COM_QUERY", "sql":"SELECT 1",
        "response":{"status":"resultset", "server_status":2,
            "columns":[{"name":"1","family":"integer","sql_type":"INT"}],
            "rows":[[{"kind":"integer","value":1}]]}
    });
    let runtime = runtime(temp.path(), &[missing], &[], true).await.unwrap();
    enable(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let started = Instant::now();
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert!(observer.ordered_fast());
    let first = observer.wait(3, vec![]).await.unwrap();
    assert!(first.removed_ms > 250);
    let second = tokio::time::timeout(Duration::from_secs(2), observer.wait(4, vec![]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.removed_ms, second.removed_ms);
    assert!(started.elapsed() >= Duration::from_millis(690));
    control.abort();
}

#[tokio::test]
async fn ordered_fast_preserves_close_gaps_after_input_at_original_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let mut request = input(400);
    let actions = request["interaction"]["actions"].as_array_mut().unwrap();
    actions.truncate(3);
    actions.extend([
        serde_json::to_value(action(4, 700, r#"423["work"]"#)).unwrap(),
        serde_json::to_value(action(5, 760, "41")).unwrap(),
        serde_json::to_value(action(6, 840, "1")).unwrap(),
    ]);
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    let mut get = recorded_exchange(
        Uuid::new_v4(),
        1,
        "GET",
        &[b"heartbeat"],
        b"+OK\r\n",
        "2020-01-01T00:00:00.700984Z",
        "2020-01-01T00:00:00.702Z",
    );
    get["response_kind"] = "simple_string".into();
    let runtime = runtime(temp.path(), &[get], &[], true).await.unwrap();
    enable(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                r#"0{"sid":"live","pingInterval":10000,"pingTimeout":10000}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "40");
        socket
            .send(Message::Text(r#"40{"sid":"ns"}"#.into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, r#"421["work"]"#);
        socket
            .send(Message::Text(r#"431["ok"]"#.into()))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(250), text(&mut socket))
                .await
                .unwrap(),
            r#"422["work"]"#
        );
        socket
            .send(Message::Text(r#"432["ok"]"#.into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, r#"423["work"]"#);
        let input_at = Instant::now();
        let (mut redis, redis_task) = connect(&runtime).await;
        assert_eq!(send(&mut redis, &[b"GET", b"heartbeat"]).await, b"+OK\r\n");
        socket
            .send(Message::Text(r#"433["ok"]"#.into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "41");
        assert!(input_at.elapsed() >= Duration::from_millis(50));
        let disconnect_at = Instant::now();
        assert_eq!(text(&mut socket).await, "1");
        assert!(disconnect_at.elapsed() >= Duration::from_millis(70));
        socket.send(Message::Close(None)).await.unwrap();
        redis_task.abort();
    });
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        crate::recorded_request::RecordedHttpClient::new(
            format!("http://{addr}"),
            Duration::from_secs(3),
            1024 * 1024,
        )
        .with_input_registration(&session, "case")
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "ordered-fast"),
    )
    .await
    .unwrap()
    .unwrap();
    let observation = result.interaction.unwrap();
    assert!(observation.end.clean);
    assert!(
        observation
            .events
            .iter()
            .any(|event| event.message.data == r#"433["ok"]"#)
    );
    target.await.unwrap();
    control.abort();
}

#[tokio::test]
async fn ordered_fast_advances_on_request_admission_and_closes_after_tail_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let mut request = input(30_000);
    request["interaction"]["actions"][2]["after"] = json!([]);
    request["interaction"]["actions"][2]["compressible_gap"] = false.into();
    request["interaction"]["actions"][2]["gap_start_ms"] = Value::Null;
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    std::fs::write(temp.path().join("case/expected-response.json"), json!({
        "interaction": {"version": crate::interaction::model::TRANSCRIPT_VERSION, "protocol": "socket_io",
            "end": {"clean":true,"reason":"client_close","offset_ms":30040,"pending":[]},
            "events":[{"offset_ms":0},{"offset_ms":1},{"offset_ms":8},{"offset_ms":30002}]}
    }).to_string()).unwrap();
    let connection = Uuid::new_v4();
    let mut publish = recorded_exchange(
        connection,
        1,
        "PUBLISH",
        &[b"jobs", b"first"],
        b":1\r\n",
        "2020-01-01T00:00:00.080Z",
        "2020-01-01T00:00:00.200Z",
    );
    publish["duration_ms"] = 500.into();
    let mut get = recorded_exchange(
        connection,
        2,
        "GET",
        &[b"tail"],
        b"+OK\r\n",
        "2020-01-01T00:00:30.001Z",
        "2020-01-01T00:00:30.010Z",
    );
    get["duration_ms"] = 250.into();
    get["response_kind"] = "simple_string".into();
    let runtime = runtime(temp.path(), &[publish, get], &[], true)
        .await
        .unwrap();
    enable(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
        let (mut redis, task) = connect(&runtime).await;
        redis
            .inner
            .write_all(&crate::redis::encode_array(&[
                b"PUBLISH", b"jobs", b"first",
            ]))
            .await
            .unwrap();
        socket
            .send(Message::Text("431[\"done\"]".into()))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(300), text(&mut socket))
                .await
                .unwrap(),
            "422[\"work\"]"
        );
        socket
            .send(Message::Text("432[\"done\"]".into()))
            .await
            .unwrap();
        assert_eq!(read(&mut redis).await, b":1\r\n");
        redis
            .inner
            .write_all(&crate::redis::encode_array(&[b"GET", b"tail"]))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.next())
                .await
                .is_err()
        );
        assert_eq!(read(&mut redis).await, b"+OK\r\n");
        assert_eq!(text(&mut socket).await, "1");
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
        .send_bytes(&serde_json::to_vec(&request).unwrap(), "ordered-fast"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(result.interaction.unwrap().end.clean);
    assert!(started.elapsed() < Duration::from_secs(2));
    target.await.unwrap();
    control.abort();
}
