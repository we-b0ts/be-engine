//! A queued partial notification cannot yet authorize its callback PUBLISH.
use super::*;

#[tokio::test]
async fn callback_admission_waits_for_real_ingress_wire_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let (cases, mut globals) = fixture(temp.path());
    let mut request: Value = serde_json::from_slice(&request_bytes()).unwrap();
    request["data"][0]["padding"] = "x".repeat(8 * 1024 * 1024).into();
    let payload = serde_json::to_vec(&request).unwrap();
    globals[1]["response"] = capture(&crate::redis::encode_array(&[
        b"message", b"jobs", &payload,
    ]));
    let runtime = runtime(temp.path(), &cases, &globals, true).await.unwrap();
    runtime
        .state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .request_begin("case")
        .unwrap();
    let (reader, sub_task) = connect(&runtime).await;
    let mut subscriber = RedisBufferedReader::new(reader.into_inner(), 16 * 1024 * 1024);
    let (mut client, client_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    assert_eq!(
        send(
            &mut client,
            &[
                b"SET",
                b"online",
                &serde_json::to_vec(&json!({"socket_id":TARGET_SID})).unwrap()
            ]
        )
        .await,
        b"+OK\r\n"
    );
    let args = vec![
        b"jobs".to_vec(),
        serde_json::to_vec(&reply(TARGET_SID)).unwrap(),
    ];
    let endpoint = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .redis
                .pubsub
                .pending_ingress_reply(Some("case"), &endpoint, "PUBLISH", &args)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let callback =
        tokio::spawn(async move { send(&mut client, &[b"PUBLISH", &args[0], &args[1]]).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !callback.is_finished(),
        "callback admitted before the notification reached TCP"
    );
    let raw = read(&mut subscriber).await;
    let frame = parse_pubsub_push(&raw).unwrap().unwrap();
    let value: Value = serde_json::from_slice(&frame.payload).unwrap();
    assert_eq!(value["room"], TARGET_SID);
    assert_eq!(
        value["data"][0]["padding"].as_str().unwrap().len(),
        8 * 1024 * 1024
    );
    assert_eq!(callback.await.unwrap(), b":1\r\n");
    let state = runtime.state.lock().await;
    assert!(state.redis.snapshot().unused_case.is_empty());
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
    drop(state);
    sub_task.abort();
    client_task.abort();
}
