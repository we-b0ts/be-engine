use super::*;
use crate::replay::ReplayStreamTiming;

pub(super) async fn fast_runtime(
    root: &Path,
    cases: &[Value],
    lazy: bool,
) -> Result<Arc<ReplayRuntime>> {
    runtime_with_timing(root, cases, &[], lazy, Some(ReplayStreamTiming::Fast)).await
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
async fn unanswered_ping_does_not_disable_ordered_fast_or_authorize_early_close() {
    for saw_ping in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("case");
        let mut request = input(400);
        let interaction = &mut request["interaction"];
        interaction["socket_io_heartbeat"] = json!({"responses":[]});
        interaction["actions"][3]["action"] = json!({"kind":"transport_end","end":"eof"});
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("request.json"), request.to_string()).unwrap();
        std::fs::write(
            directory.join("expected-response.json"),
            json!({
                "interaction": {
                    "version": crate::interaction::model::TRANSCRIPT_VERSION,
                    "protocol": "socket_io",
                    "end": {"clean":true,"reason":"client_transport_end","offset_ms":445,"pending":[3]},
                    "events": [
                        {"offset_ms":1},
                        {"offset_ms":420,"heartbeat":saw_ping}
                    ]
                }
            }).to_string(),
        )
        .unwrap();
        let runtime = fast_runtime(temp.path(), &[], true).await.unwrap();
        let (session, control) = serve_control(temp.path(), &runtime).await;
        let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
            .await
            .unwrap();
        assert!(observer.ordered_fast());
        assert!(observer.fast_tail().is_none());
        control.abort();
    }
}

#[tokio::test]
async fn ordered_fast_reports_missing_admission_past_the_source_deadline() {
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
    let runtime = fast_runtime(temp.path(), &[missing], true).await.unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let started = Instant::now();
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert!(observer.ordered_fast());
    let first = observer.wait(3, vec![]).await.unwrap();
    assert!(first.removed_ms > 250);
    let (_gate, gate) = tokio::sync::watch::channel(true);
    let (missing_request, witness) = tokio::sync::watch::channel(None);
    let second = tokio::time::timeout(
        Duration::from_millis(850),
        observer.wait_dispatch(4, vec![], gate, missing_request),
    )
    .await;
    assert!(
        second.is_err(),
        "the recorded deadline must not release an unadmitted request"
    );
    assert!(matches!(
        witness.borrow().as_ref(),
        Some(reference) if reference.protocol() == "mysql" && reference.fields()["sequence"] == 1
    ));
    assert!(started.elapsed() >= Duration::from_millis(850));
    control.abort();
}

#[tokio::test]
async fn ordered_fast_rechecks_a_request_in_the_previous_input_bucket() {
    let temp = tempfile::tempdir().unwrap();
    let mut request = input(400);
    let actions = request["interaction"]["actions"].as_array_mut().unwrap();
    actions[2]["after"] = json!([]);
    actions[2]["compressible_gap"] = false.into();
    actions[2]["gap_start_ms"] = Value::Null;
    actions.truncate(3);
    actions.push(serde_json::to_value(action(4, 30_000, r#"423["work"]"#)).unwrap());
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    let mut get = recorded_exchange(
        Uuid::new_v4(),
        1,
        "GET",
        &[b"previous"],
        b"+OK\r\n",
        "2020-01-01T00:00:00.400586Z",
        "2020-01-01T00:00:00.402Z",
    );
    get["response_kind"] = "simple_string".into();
    let runtime = fast_runtime(temp.path(), &[get], true).await.unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert!(observer.ordered_fast());
    observer.wait(3, vec![]).await.unwrap();

    let (_events, gate) = tokio::sync::watch::channel(true);
    let (missing, witness) = tokio::sync::watch::channel(None);
    let mut pending = observer.wait_dispatch(4, vec![], gate, missing);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    assert!(witness.borrow().is_none());
    let (mut redis, task) = connect(&runtime).await;
    assert_eq!(send(&mut redis, &[b"GET", b"previous"]).await, b"+OK\r\n");
    let advance = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("admission must wake the compressed dispatch before its Source offset")
        .unwrap();
    assert!(advance.removed_ms > 28_000);
    task.abort();
    control.abort();
}

#[tokio::test]
async fn ordered_fast_compresses_legacy_millisecond_input_and_preserves_close_gaps() {
    replay_close_gaps(false).await;
}

#[tokio::test]
async fn ordered_fast_compresses_when_its_own_get_follows_a_precise_input() {
    replay_close_gaps(true).await;
}

async fn replay_close_gaps(precise: bool) {
    let temp = tempfile::tempdir().unwrap();
    let mut request = input(400);
    let actions = request["interaction"]["actions"].as_array_mut().unwrap();
    actions.truncate(3);
    actions.extend([
        serde_json::to_value(action(4, 30_000, r#"423["work"]"#)).unwrap(),
        serde_json::to_value(action(5, 30_060, "41")).unwrap(),
        serde_json::to_value(action(6, 30_140, "1")).unwrap(),
    ]);
    if precise {
        actions[3]["offset_us"] = 30_000_123.into();
    }
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
    let mut get = recorded_exchange(
        Uuid::new_v4(),
        1,
        "GET",
        &[b"heartbeat"],
        b"+OK\r\n",
        "2020-01-01T00:00:30.000984Z",
        "2020-01-01T00:00:30.002Z",
    );
    get["response_kind"] = "simple_string".into();
    let runtime = fast_runtime(temp.path(), &[get], true).await.unwrap();
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
        let third = tokio::time::timeout(Duration::from_millis(300), text(&mut socket))
            .await
            .expect("the later GET must not pin this input");
        assert_eq!(third, r#"423["work"]"#);
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
    let payload = vec![b'x'; 6 * 1024 * 1024];
    let mut tail_response = format!("${}\r\n", payload.len()).into_bytes();
    tail_response.extend_from_slice(&payload);
    tail_response.extend_from_slice(b"\r\n");
    let mut get = recorded_exchange(
        connection,
        2,
        "GET",
        &[b"tail"],
        &tail_response,
        "2020-01-01T00:00:30.001Z",
        "2020-01-01T00:00:30.010Z",
    );
    get["duration_ms"] = 250.into();
    get["response_kind"] = "bulk_string".into();
    let runtime = fast_runtime(temp.path(), &[publish, get], true)
        .await
        .unwrap();
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
        redis.max_frame_bytes = 8 * 1024 * 1024;
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
        assert_eq!(read(&mut redis).await, tail_response);
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

#[tokio::test]
async fn ordered_fast_reports_unadmitted_http_in_the_case_dispatch_timeout() {
    use crate::interaction::model::{DispatchDependency, DispatchStage, EndReason};

    let temp = tempfile::tempdir().unwrap();
    let mut request = input(30_000);
    let actions = request["interaction"]["actions"].as_array_mut().unwrap();
    actions[2]["after"] = json!([]);
    actions[2]["compressible_gap"] = false.into();
    actions[2]["gap_start_ms"] = Value::Null;
    actions.insert(
        3,
        serde_json::to_value(action(4, 30_001, r#"423["work"]"#)).unwrap(),
    );
    actions[4]["sequence"] = 5.into();
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    let path = temp.path().join("case/request.json");
    std::fs::write(&path, request.to_string()).unwrap();
    let exchange_id = Uuid::new_v4();
    let http = json!({
        "event_type": "http_exchange",
        "id": exchange_id,
        "scheme": "http",
        "authority": "http.test",
        "method": "POST",
        "uri": "/work",
        "request_started_at": "2020-01-01T00:00:00.080Z",
        "timestamp": "2020-01-01T00:00:00.100Z",
        "request_body": capture(b""),
        "response_status": 200,
        "response_headers": {},
        "response_body": capture(b"ok")
    });
    let runtime = fast_runtime(temp.path(), &[http], true).await.unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
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
        assert!(matches!(socket.next().await, None | Some(Err(_))));
    });

    let response = tokio::time::timeout(
        Duration::from_secs(7),
        crate::recorded_request::RecordedHttpClient::new(
            format!("http://{address}"),
            Duration::from_secs(7),
            1024 * 1024,
        )
        .with_input_registration(&session, "case")
        .send_recorded_bytes(&serde_json::to_vec(&request).unwrap(), &path),
    )
    .await
    .expect("the missing HTTP must not fall back to the 30-second input offset")
    .unwrap();
    let end = response.interaction.unwrap().end;
    assert_eq!(end.reason, EndReason::DispatchTimeout);
    assert!((5_000..7_000).contains(&end.offset_ms));
    let timeout = end.dispatch_timeout.unwrap();
    assert_eq!(timeout.input_sequence, 3);
    assert_eq!(timeout.stage, DispatchStage::Prerequisites);
    assert_eq!(
        timeout.unadmitted_request,
        Some(DispatchDependency::exchange("http", exchange_id))
    );
    target.await.unwrap();
    control.abort();
}
