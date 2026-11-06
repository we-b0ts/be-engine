//! Socket.IO business events and resource delivery use independent evidence.
use super::*;

#[tokio::test]
async fn business_input_waits_for_recorded_events_even_without_redis_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = InputTranscript::new(
        Protocol::SocketIo,
        InteractionPolicy {
            business_idle_ms: 1_000,
            cleanup_timeout_ms: 500,
            max_duration_ms: 3_000,
            request_timeout_ms: 3_000,
            ..Default::default()
        },
    );
    input.actions = vec![
        action(1, 0, "40"),
        action(2, 5, "421[\"register\"]"),
        action(3, 40, "42[\"heartbeat\"]"),
        action(4, 600, "1"),
    ];
    input.actions[1].after = vec![1];
    let request = json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket",
        "timestamp":START,"headers":{},"body":capture(b""),"interaction":input});
    std::fs::create_dir_all(temp.path().join("case")).unwrap();
    let path = temp.path().join("case/request.json");
    std::fs::write(&path, request.to_string()).unwrap();
    let original = std::fs::read(&path).unwrap();
    std::fs::write(
        temp.path().join("case/expected-response.json"),
        json!({"interaction": {
            "version": crate::interaction::model::TRANSCRIPT_VERSION,
            "protocol":"socket_io",
            "events":[
                {"sequence":1,"offset_ms":24,"message":{"kind":"text","data":"431[true]"}},
                {"sequence":2,"offset_ms":26,"message":{"kind":"text","data":"42/other,[\"ready\"]"}}
            ],
            "end":{"reason":"client_close","offset_ms":600,"clean":true}
        }}).to_string(),
    ).unwrap();
    let connection = Uuid::new_v4();
    let mut set = exchange(connection, 1, "SET", &[b"registered", b"yes"], b"+OK\r\n");
    set["response_kind"] = "simple_string".into();
    set["timestamp"] = "2020-01-01T00:00:00.020Z".into();
    set["request_started_at"] = "2020-01-01T00:00:00.010Z".into();
    let mut get = exchange(
        connection,
        2,
        "GET",
        &[b"after-heartbeat"],
        b"$3\r\nyes\r\n",
    );
    get["response_kind"] = "bulk_string".into();
    get["timestamp"] = "2020-01-01T00:00:00.055Z".into();
    get["request_started_at"] = "2020-01-01T00:00:00.030Z".into();
    get["duration_ms"] = 25.into();
    let runtime = runtime(temp.path(), &[set, get], &[], false).await.unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
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
        assert_eq!(text(&mut socket).await, "421[\"register\"]");
        socket
            .send(Message::Text("431[true]".into()))
            .await
            .unwrap();
        socket.send(Message::Text("2live".into())).await.unwrap();
        assert_eq!(text(&mut socket).await, "3live");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.next())
                .await
                .is_err()
        );
        socket
            .send(Message::Text(r#"42/other,["ready"]"#.into()))
            .await
            .unwrap();
        assert_eq!(text(&mut socket).await, "42[\"heartbeat\"]");
        // A Source Redis response before the heartbeat is not an event barrier.
        let (mut redis, task) = connect(&target_runtime).await;
        assert_eq!(
            send(&mut redis, &[b"SET", b"registered", b"yes"]).await,
            b"+OK\r\n"
        );
        // Source started this dependency before the heartbeat but finished it
        // afterward. Its overlapping handler must not block the next input.
        assert_eq!(
            send(&mut redis, &[b"GET", b"after-heartbeat"]).await,
            b"$3\r\nyes\r\n"
        );
        assert_eq!(text(&mut socket).await, "1");
        socket.send(Message::Close(None)).await.unwrap();
        task.abort();
    });
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        crate::recorded_request::RecordedHttpClient::new(
            format!("http://{address}"),
            Duration::from_secs(3),
            1024 * 1024,
        )
        .with_input_registration(&session, "case")
        .send_recorded_bytes(&serde_json::to_vec(&request).unwrap(), &path),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.interaction.unwrap().end.clean);
    target.await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), original);
    control.abort();
}

fn write_program(root: &Path, next_ms: u64) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    std::fs::write(root.join("case/request.json"), input(next_ms).to_string()).unwrap();
}

fn prior_set(duration_ms: u64) -> Value {
    let mut record = exchange(
        Uuid::new_v4(),
        1,
        "SET",
        &[b"registered", b"yes"],
        b"+OK\r\n",
    );
    record["response_kind"] = "simple_string".into();
    record["timestamp"] = "2020-01-01T00:00:00.180Z".into();
    record["duration_ms"] = duration_ms.into();
    record
}

#[tokio::test]
async fn actual_response_before_timing_admission_remains_a_delivery_proof() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 30_000);
    let runtime = runtime(temp.path(), &[prior_set(0)], &[], false)
        .await
        .unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut redis, &[b"SET", b"registered", b"yes"]).await,
        b"+OK\r\n"
    );
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    let advance = tokio::time::timeout(Duration::from_secs(1), observer.wait(3, vec![2]))
        .await
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    redis_task.abort();
    control.abort();
}

#[tokio::test]
async fn response_started_before_timing_admission_is_recorded_only_after_actual_write() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 30_000);
    let runtime = runtime(temp.path(), &[prior_set(300)], &[], false)
        .await
        .unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    redis
        .inner
        .write_all(&crate::redis::encode_array(&[
            b"SET",
            b"registered",
            b"yes",
        ]))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .redis
                .exchanges
                .iter()
                .any(|exchange| exchange.status == ReplayExchangeStatus::Responding)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    let mut wait = tokio::spawn(async move { observer.wait(3, vec![2]).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut wait)
            .await
            .is_err()
    );
    assert_eq!(read(&mut redis).await, b"+OK\r\n");
    let advance = tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    redis_task.abort();
    control.abort();
}

#[tokio::test]
async fn same_case_new_epoch_cannot_borrow_an_earlier_actual_response() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 400);
    let runtime = runtime(temp.path(), &[prior_set(0)], &[], false)
        .await
        .unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut redis, &[b"SET", b"registered", b"yes"]).await,
        b"+OK\r\n"
    );
    runtime.state.lock().await.advance_admission_epoch();
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(600), observer.wait(3, vec![2]))
            .await
            .is_err()
    );
    redis_task.abort();
    control.abort();
}

#[tokio::test]
async fn native_push_before_timing_admission_retains_its_actual_wire_receipt() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 30_000);
    let subscription = Uuid::new_v4();
    let publisher = Uuid::new_v4();
    let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let source_request = request(SOURCE, 1);
    let mut publication = exchange(
        publisher,
        1,
        "PUBLISH",
        &[b"jobs", &source_request],
        b":2\r\n",
    );
    publication["timestamp"] = "2020-01-01T00:00:00.100Z".into();
    let bytes = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
    let mut notification = push(subscription, Some(publisher), &bytes, 80);
    notification["timestamp"] = "2020-01-01T00:00:00.180Z".into();
    let runtime = runtime(
        temp.path(),
        &[publication, notification],
        &[exchange(
            subscription,
            1,
            "SUBSCRIBE",
            &[b"jobs"],
            confirmed,
        )],
        false,
    )
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
    let delivered = tokio::time::timeout(Duration::from_secs(1), read(&mut subscriber))
        .await
        .unwrap();
    let frame = parse_pubsub_push(&delivered).unwrap().unwrap();
    let (identity, value) = rpc::callback(&frame.payload).unwrap().unwrap();
    assert_eq!(identity.host, TARGET);
    assert_eq!(identity.id, 9);
    assert_eq!(value["args"][0]["stdout"], "example result");
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    let advance = tokio::time::timeout(Duration::from_secs(1), observer.wait(3, vec![2]))
        .await
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    pub_task.abort();
    sub_task.abort();
    control.abort();
}

#[tokio::test]
async fn shared_subscription_write_survives_startup_but_business_receipt_remains_epoch_bound() {
    for owner in [None, Some("another-case")] {
        let temp = tempfile::tempdir().unwrap();
        write_program(temp.path(), 400);
        let subscription = Uuid::new_v4();
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let mut setup = exchange(subscription, 1, "SUBSCRIBE", &[b"jobs"], confirmed);
        setup["timestamp"] = "2020-01-01T00:00:00.001Z".into();
        let mut business = exchange(Uuid::new_v4(), 1, "GET", &[b"private"], b"$1\r\nv\r\n");
        business["response_kind"] = "bulk_string".into();
        business["timestamp"] = "2020-01-01T00:00:00.180Z".into();
        let notification = push(
            subscription,
            None,
            &crate::redis::encode_array(&[b"message", b"jobs", b"process-notification"]),
            20,
        );
        let runtime = runtime(temp.path(), &[setup, business], &[notification], false)
            .await
            .unwrap();
        let (mut business_client, business_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut business_client, &[b"GET", b"private"]).await,
            b"$1\r\nv\r\n"
        );
        {
            let mut state = runtime.state.lock().await;
            assert!(
                state
                    .redis
                    .exchanges
                    .iter()
                    .any(|exchange| exchange.subscription_alias)
            );
            state.advance_admission_epoch();
            state.active_case_id = owner.map(str::to_owned);
        }
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        // Successful process notification delivery proves the alias's shared
        // subscription path, independent of the currently active Case.
        let raw = read(&mut subscriber).await;
        assert_eq!(
            parse_pubsub_push(&raw).unwrap().unwrap().payload,
            b"process-notification"
        );
        {
            let mut state = runtime.state.lock().await;
            state.advance_admission_epoch();
            state.active_case_id = Some("case".into());
        }
        let (session, control) = serve_control(temp.path(), &runtime).await;
        let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
            .await
            .unwrap();
        // Only the actual shared SUBSCRIBE reply precedes input 2. Its original
        // Case may rely on that process setup delivered before this request.
        tokio::time::timeout(Duration::from_millis(300), observer.wait(2, vec![1]))
            .await
            .unwrap()
            .unwrap();
        // Input 3 additionally needs the private GET, delivered in an older
        // business epoch. The subscription authority must not authorize it.
        assert!(
            tokio::time::timeout(Duration::from_millis(600), observer.wait(3, vec![2]))
                .await
                .is_err()
        );
        business_task.abort();
        sub_task.abort();
        control.abort();
    }
}
