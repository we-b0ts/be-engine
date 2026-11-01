//! Self-echo lookup preparation precedes Target admission and retains finite delivery.
use super::*;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

fn broadcast(host: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&request(host, 1)).unwrap();
    value["callback"] = Value::Null;
    serde_json::to_vec(&value).unwrap()
}

fn notification_lane(
    host: &str,
    command: &str,
    subject: &str,
    channel: &[u8],
    payload: &[u8],
) -> Vec<Value> {
    let subscription = Uuid::new_v4();
    let confirmed = format!(
        "*3\r\n${}\r\n{}\r\n${}\r\n{}\r\n:1\r\n",
        command.len(),
        command.to_ascii_lowercase(),
        subject.len(),
        subject,
    );
    let mut subscribe = exchange(
        subscription,
        1,
        command,
        &[subject.as_bytes()],
        confirmed.as_bytes(),
    );
    let parts: Vec<&[u8]> = match command {
        "PSUBSCRIBE" => vec![b"pmessage", subject.as_bytes(), channel, payload],
        "SSUBSCRIBE" => vec![b"smessage", channel, payload],
        _ => vec![b"message", channel, payload],
    };
    let mut notification = push(
        subscription,
        None,
        &crate::redis::encode_array(&parts),
        600_000,
    );
    subscribe["target_host"] = host.into();
    notification["target_host"] = host.into();
    vec![subscribe, notification]
}

#[tokio::test]
async fn readiness_prepares_only_relevant_lanes_for_case_and_startup_publishers() {
    for lazy in [false, true] {
        for global_publisher in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let source = broadcast(SOURCE);
            let publisher = exchange(Uuid::new_v4(), 1, "PUBLISH", &[b"jobs", &source], b":1\r\n");
            let mut globals = Vec::new();
            for (host, command, subject, channel) in [
                ("redis.test", "SUBSCRIBE", "jobs", b"jobs".as_slice()),
                ("redis.test", "SUBSCRIBE", "other", b"other".as_slice()),
                ("other.test", "SUBSCRIBE", "jobs", b"jobs".as_slice()),
                ("redis.test", "PSUBSCRIBE", "job*", b"jobs".as_slice()),
                ("redis.test", "SSUBSCRIBE", "jobs", b"jobs".as_slice()),
            ] {
                globals.extend(notification_lane(host, command, subject, channel, &source));
            }
            let cases = if global_publisher {
                globals.push(publisher);
                Vec::new()
            } else {
                vec![publisher]
            };
            let runtime = runtime(temp.path(), &cases, &globals, lazy).await.unwrap();
            let prepared = {
                let state = runtime.state.lock().await;
                assert_eq!(state.redis.events.connections, 0);
                assert!(state.redis.pubsub.subscriptions.is_empty());
                assert_eq!(state.redis.pubsub.indexed.delivered, 0);
                assert_eq!(state.redis.pubsub.indexed.lanes.len(), 5);
                state
                    .redis
                    .pubsub
                    .indexed
                    .lanes
                    .iter()
                    .map(|lane| {
                        let expected = lane.record.target_host == "redis.test"
                            && (lane.kind == RedisSubscriptionKind::Pattern
                                || lane.kind == RedisSubscriptionKind::Channel
                                    && lane.subject == b"jobs");
                        assert_eq!(lane.echoes.get().is_some(), expected);
                        if let Some(index) = lane.echoes.get() {
                            assert_eq!(index.as_ref().unwrap().len(), 1);
                        }
                        lane.echoes.clone()
                    })
                    .collect::<Vec<_>>()
            };
            let next = load_runtime(temp.path(), lazy).await.unwrap();
            let state = next.state.lock().await;
            for (old, lane) in prepared.iter().zip(&state.redis.pubsub.indexed.lanes) {
                assert!(!Arc::ptr_eq(old, &lane.echoes));
                assert_eq!(old.get().is_some(), lane.echoes.get().is_some());
            }
            assert_eq!(state.redis.pubsub.indexed.delivered, 0);
        }
    }
}

#[tokio::test]
async fn ordinary_publishers_do_not_prepare_adapter_echo_indices() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let globals = notification_lane(
            "redis.test",
            "SUBSCRIBE",
            "jobs",
            b"jobs",
            &broadcast(SOURCE),
        );
        let runtime = runtime(
            temp.path(),
            &[exchange(
                Uuid::new_v4(),
                1,
                "PUBLISH",
                &[b"jobs", b"opaque-application-message"],
                b":1\r\n",
            )],
            &globals,
            lazy,
        )
        .await
        .unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.pubsub.indexed.lanes.len(), 1);
        assert!(state.redis.pubsub.indexed.lanes[0].echoes.get().is_none());
    }
}

#[tokio::test]
async fn prepared_self_echo_preserves_pipelined_publish_delete_and_live_payload() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let subscription = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let source = broadcast(SOURCE);
        let actual = broadcast(TARGET);
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
        let mut globals = vec![exchange(
            subscription,
            1,
            "SUBSCRIBE",
            &[b"jobs"],
            CONFIRMED,
        )];
        for _ in 0..513 {
            globals.push(push(
                subscription,
                None,
                &crate::redis::encode_array(&[b"message", b"jobs", b"background"]),
                600_000,
            ));
        }
        globals.push(push(subscription, None, &raw, 600_000));
        let runtime = runtime(
            temp.path(),
            &[
                exchange(publisher, 1, "PUBLISH", &[b"jobs", &source], b":1\r\n"),
                exchange(publisher, 2, "DEL", &[b"key"], b":1\r\n"),
            ],
            &globals,
            lazy,
        )
        .await
        .unwrap();
        let prepared = {
            let state = runtime.state.lock().await;
            let lane = &state.redis.pubsub.indexed.lanes[0];
            assert!(lane.pages.as_ref().unwrap().pages() > 1);
            assert!(lane.echoes.get().unwrap().is_ok());
            lane.echoes.clone()
        };
        let (mut subscriber, subscriber_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        let (mut client, client_task) = connect(&runtime).await;
        let mut pipeline = crate::redis::encode_array(&[b"PUBLISH", b"jobs", &actual]);
        pipeline.extend(crate::redis::encode_array(&[b"DEL", b"key"]));
        client.inner.write_all(&pipeline).await.unwrap();
        assert_eq!(read(&mut client).await, b":1\r\n");
        assert_eq!(read(&mut client).await, b":1\r\n");
        let received = read(&mut subscriber).await;
        assert_eq!(
            parse_pubsub_push(&received).unwrap().unwrap().payload,
            actual
        );
        send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &actual]).await;
        let state = runtime.state.lock().await;
        assert!(Arc::ptr_eq(
            &prepared,
            &state.redis.pubsub.indexed.lanes[0].echoes
        ));
        assert!(state.redis.snapshot().unused_case.is_empty());
        assert_eq!(state.redis.pubsub.indexed.delivered, 1);
        assert_eq!(state.redis.pubsub.global_unused_count(), 513);
        client_task.abort();
        subscriber_task.abort();
    }
}
