//! Non-RPC adapter emissions share the manager identity while keeping business fields exact.
use super::*;
use std::time::Duration;

fn broadcast(host: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&request(host, 1)).unwrap();
    value["callback"] = Value::Null;
    serde_json::to_vec(&value).unwrap()
}

#[tokio::test]
async fn compact_broadcast_delivers_the_finite_echo_with_target_bytes() {
    let payload = |host| {
        serde_json::to_vec(&json!({
            "method": "emit", "event": "work:run", "data": [{"job": 7}],
            "namespace": "/worker", "room": "worker:1", "host_id": host,
        }))
        .unwrap()
    };
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let source = payload(SOURCE);
        let target = payload(TARGET);
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let runtime = runtime(
            temp.path(),
            &[exchange(
                publisher,
                1,
                "PUBLISH",
                &[b"jobs", &source],
                b":1\r\n",
            )],
            &[
                exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed),
                push(sub, None, &raw, 600_000),
            ],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &target]).await,
            b":1\r\n"
        );
        let received = read(&mut subscriber).await;
        assert_eq!(
            parse_pubsub_push(&received).unwrap().unwrap().payload,
            target
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), read_redis_frame(&mut subscriber))
                .await
                .is_err()
        );
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
        task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn ordinary_broadcast_translates_only_host_and_delivers_one_finite_echo() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let pub_id = Uuid::new_v4();
        let source = broadcast(SOURCE);
        let actual = broadcast(TARGET);
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let mut rpc_publish = exchange(
            pub_id,
            2,
            "PUBLISH",
            &[b"jobs", &request(SOURCE, 1)],
            b":1\r\n",
        );
        rpc_publish["rpc_callback_capture"] = "bounded_window".into();
        let runtime = runtime(
            temp.path(),
            &[
                exchange(pub_id, 1, "PUBLISH", &[b"jobs", &source], b":1\r\n"),
                rpc_publish,
            ],
            &[
                exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed),
                push(sub, None, &raw, 600_000),
            ],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        let (mut client, mut task) = connect(&runtime).await;
        for pointer in ["/room", "/event", "/data/0/argv/0"] {
            let mut wrong: Value = serde_json::from_slice(&actual).unwrap();
            *wrong.pointer_mut(pointer).unwrap() = "changed".into();
            send_unmatched(
                &mut client,
                &[b"PUBLISH", b"jobs", &serde_json::to_vec(&wrong).unwrap()],
            )
            .await;
            reconnect(&runtime, &mut client, &mut task).await;
        }
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
            b":1\r\n"
        );
        let received = read(&mut subscriber).await;
        assert_eq!(
            parse_pubsub_push(&received).unwrap().unwrap().payload,
            actual
        );
        let different = Uuid::new_v4().simple().to_string();
        send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &request(&different, 9)]).await;
        reconnect(&runtime, &mut client, &mut task).await;
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":1\r\n"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), read_redis_frame(&mut subscriber))
                .await
                .is_err()
        );
        let state = runtime.state.lock().await;
        assert!(state.redis.snapshot().unused_case.is_empty());
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
        task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn recorded_publish_error_remains_a_matched_result_without_sending_an_echo() {
    let temp = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let publisher = Uuid::new_v4();
    let source = broadcast(SOURCE);
    let actual = broadcast(TARGET);
    let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
    let mut error = exchange(
        publisher,
        1,
        "PUBLISH",
        &[b"jobs", &source],
        b"-ERR recorded failure\r\n",
    );
    error["response_kind"] = "error".into();
    let runtime = runtime(
        temp.path(),
        &[
            error,
            exchange(publisher, 2, "PUBLISH", &[b"jobs", &source], b":1\r\n"),
        ],
        &[
            exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed),
            push(sub, None, &raw, 600_000),
        ],
        true,
    )
    .await
    .unwrap();
    let (mut subscriber, sub_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        confirmed
    );
    let (mut client, pub_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
        b"-ERR recorded failure\r\n"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_redis_frame(&mut subscriber))
            .await
            .is_err()
    );
    assert!(
        !runtime
            .state
            .lock()
            .await
            .redis
            .case_has_runtime_failure("case")
    );
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
        b":1\r\n"
    );
    assert_eq!(
        parse_pubsub_push(&read(&mut subscriber).await)
            .unwrap()
            .unwrap()
            .payload,
        actual
    );
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
    pub_task.abort();
    sub_task.abort();
}
