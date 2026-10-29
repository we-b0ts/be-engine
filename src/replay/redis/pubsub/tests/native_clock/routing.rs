use super::*;

async fn other_connection(
    runtime: &Arc<ReplayRuntime>,
) -> (
    RedisBufferedReader<TcpStream>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "other.test".into(),
            port: 6379,
            fake_ip: "198.18.0.2".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    (RedisBufferedReader::new(stream, 64 * 1024 * 1024), task)
}

#[tokio::test]
async fn original_order_and_subscription_realm_survive_late_correct_subscription() {
    let temp = tempfile::tempdir().unwrap();
    let (mut globals, first) = fixture(temp.path());
    let mut other = exchange(Uuid::new_v4(), 1, "SUBSCRIBE", &[b"jobs"], SUBSCRIBED);
    other["target_host"] = "other.test".into();
    globals.push(other);
    let frame = parse_pubsub_push(&first).unwrap().unwrap();
    let mut body: Value = serde_json::from_slice(&frame.payload).unwrap();
    body["data"] = json!([{"value":8}]);
    let second =
        crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(&body).unwrap()]);
    let mut later = globals[1].clone();
    later["timestamp"] = "2020-01-01T00:10:00.080Z".into();
    later["duration_ms"] = 600080.into();
    later["response"] = capture(&second);
    globals.push(later);
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let (mut other, other_task) = other_connection(&runtime).await;
    assert_eq!(send(&mut other, &[b"SUBSCRIBE", b"jobs"]).await, SUBSCRIBED);
    let epoch = guards::begin(&runtime).await;
    assert_eq!(
        guards::connected(&runtime, epoch, "/chat").await["ok"],
        true
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(110), read_redis_frame(&mut other))
            .await
            .is_err()
    );
    let (mut correct, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut correct, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    assert_eq!(read(&mut correct).await, first);
    assert_eq!(read(&mut correct).await, second);
    guards::silent(&mut other).await;
    guards::silent(&mut correct).await;
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
        2
    );
    task.abort();
    other_task.abort();
}
