//! Native adapter self-echo admission, fresh session identities and finite delivery.
use super::*;
const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

fn with_sid(bytes: &[u8], sid: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    value["room"] = sid.into();
    value["callback"][0] = sid.into();
    serde_json::to_vec(&value).unwrap()
}
fn publisher(connection: Uuid, sequence: u64, payload: &[u8]) -> Value {
    let mut value = exchange(
        connection,
        sequence,
        "PUBLISH",
        &[b"jobs", payload],
        b":1\r\n",
    );
    value["rpc_callback_capture"] = "bounded_window".into();
    value
}

#[tokio::test]
async fn matched_publish_echoes_actual_payload_without_recorded_idle_or_duplicate_delivery() {
    for (lazy, delay) in [(false, 0), (true, 0), (false, 600_000), (true, 600_000)] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher_id = Uuid::new_v4();
        let source = with_sid(&request(SOURCE, 1), "source-session");
        let actual = with_sid(&request(TARGET, 9), "target-session");
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
        let runtime = runtime(
            temp.path(),
            &[publisher(publisher_id, 1, &source)],
            &[
                exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
                push(sub, None, &raw, delay),
            ],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                read_redis_frame(&mut subscriber)
            )
            .await
            .is_err()
        );
        let (mut client, mut task) = connect(&runtime).await;
        let mut wrong: Value = serde_json::from_slice(&actual).unwrap();
        wrong["data"][0]["argv"] = json!(["unselected-business-change"]);
        send_unmatched(
            &mut client,
            &[b"PUBLISH", b"jobs", &serde_json::to_vec(&wrong).unwrap()],
        )
        .await;
        reconnect(&runtime, &mut client, &mut task).await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                read_redis_frame(&mut subscriber)
            )
            .await
            .is_err()
        );
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
            b":1\r\n"
        );
        let received = read(&mut subscriber).await;
        let frame = parse_pubsub_push(&received).unwrap().unwrap();
        assert_eq!(frame.payload, actual);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(40),
                read_redis_frame(&mut subscriber)
            )
            .await
            .is_err()
        );
        let state = runtime.state.lock().await;
        assert_eq!(
            state
                .protocols
                .redis
                .pubsub
                .report()
                .unwrap()
                .delivered_pushes,
            1
        );
        assert_eq!(
            state
                .protocols
                .redis
                .pubsub
                .report()
                .unwrap()
                .delivered_rpc_callbacks,
            0
        );
        assert!(state.protocols.redis.snapshot().unused_case.is_empty());
        assert!(
            state
                .protocols
                .redis
                .pubsub
                .unused(ReplaySource::Startup)
                .is_empty()
        );
        task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn session_bindings_are_bijective_and_callbacks_use_the_live_session() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let pub_id = Uuid::new_v4();
    let source = with_sid(&request(SOURCE, 1), "source-one");
    let second = with_sid(&request(SOURCE, 2), "source-two");
    let third = with_sid(&request(SOURCE, 3), "source-one");
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &{
        let mut value: Value = serde_json::from_slice(&callback(SOURCE, 1)).unwrap();
        value["sid"] = "source-one".into();
        serde_json::to_vec(&value).unwrap()
    }]);
    let runtime = runtime(
        temp.path(),
        &[
            publisher(pub_id, 1, &source),
            push(sub, Some(pub_id), &raw, 1),
            publisher(pub_id, 2, &second),
            publisher(pub_id, 3, &third),
        ],
        &[exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED)],
        false,
    )
    .await
    .unwrap();
    let (mut subscriber, sub_task) = connect(&runtime).await;
    send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await;
    let (mut client, mut task) = connect(&runtime).await;
    let first = with_sid(&request(TARGET, 9), "live-one");
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &first]).await,
        b":1\r\n"
    );
    let received = read(&mut subscriber).await;
    let payload = parse_pubsub_push(&received).unwrap().unwrap().payload;
    assert_eq!(rpc::callback(&payload).unwrap().unwrap().0.sid, "live-one");
    let collision = with_sid(&request(TARGET, 10), "live-one");
    send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &collision]).await;
    reconnect(&runtime, &mut client, &mut task).await;
    let second = with_sid(&request(TARGET, 10), "live-two");
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &second]).await,
        b":1\r\n"
    );
    let rebinding = with_sid(&request(TARGET, 11), "live-three");
    send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &rebinding]).await;
    reconnect(&runtime, &mut client, &mut task).await;
    let valid = with_sid(&request(TARGET, 11), "live-one");
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &valid]).await,
        b":1\r\n"
    );
    task.abort();
    sub_task.abort();
}

#[tokio::test]
async fn self_echo_preserves_its_exact_subscription_across_redis_logical_databases() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let source = request(SOURCE, 1);
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
    let mut subscribe = exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED);
    subscribe["database"] = 1.into();
    let mut notification = push(sub, None, &raw, 20);
    notification["database"] = 1.into();
    let runtime = runtime(
        temp.path(),
        &[publisher(Uuid::new_v4(), 1, &source)],
        &[subscribe, notification],
        true,
    )
    .await
    .unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(send(&mut subscriber, &[b"SELECT", b"1"]).await, b"+OK\r\n");
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        CONFIRMED
    );
    let (mut client, pub_task) = connect(&runtime).await;
    let actual = with_sid(&request(TARGET, 9), "live-session");
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
        b":1\r\n"
    );
    let received = read(&mut subscriber).await;
    assert_eq!(
        parse_pubsub_push(&received).unwrap().unwrap().payload,
        actual
    );
    pub_task.abort();
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .redis
            .pubsub
            .report()
            .unwrap()
            .delivered_pushes,
        1
    );
    task.abort();
}

#[tokio::test]
async fn source_proven_echo_routes_through_its_pattern_subscription() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let source = request(SOURCE, 1);
    let raw = crate::redis::encode_array(&[b"pmessage", b"job*", b"jobs", &source]);
    let confirmed = b"*3\r\n$10\r\npsubscribe\r\n$4\r\njob*\r\n:1\r\n";
    let runtime = runtime(
        temp.path(),
        &[publisher(Uuid::new_v4(), 1, &source)],
        &[
            exchange(sub, 1, "PSUBSCRIBE", &[b"job*"], confirmed),
            push(sub, None, &raw, 600_000),
        ],
        true,
    )
    .await
    .unwrap();
    let (mut subscriber, sub_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"PSUBSCRIBE", b"job*"]).await,
        confirmed
    );
    let (mut client, pub_task) = connect(&runtime).await;
    let actual = with_sid(&request(TARGET, 9), "live-session");
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
        b":1\r\n"
    );
    let received = read(&mut subscriber).await;
    let push = parse_pubsub_push(&received).unwrap().unwrap();
    assert_eq!(push.subject, b"job*");
    assert_eq!(push.channel, b"jobs");
    assert_eq!(push.payload, actual);
    sub_task.abort();
    pub_task.abort();
}

#[tokio::test]
async fn unrelated_native_adapter_notification_retains_recorded_bytes_and_timer() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let source = request(SOURCE, 1);
    let unrelated = request(SOURCE, 2);
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &unrelated]);
    let runtime = runtime(
        temp.path(),
        &[publisher(Uuid::new_v4(), 1, &source)],
        &[
            exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
            push(sub, None, &raw, 20),
        ],
        true,
    )
    .await
    .unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        CONFIRMED
    );
    assert_eq!(read(&mut subscriber).await, raw);
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .redis
            .pubsub
            .report()
            .unwrap()
            .delivered_pushes,
        1
    );
    task.abort();
}
