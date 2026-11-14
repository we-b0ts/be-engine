use super::*;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

fn subscribe(connection: Uuid) -> Value {
    exchange(connection, 4, "SUBSCRIBE", &[b"jobs"], CONFIRMED)
}

fn rpc_records(subscriber: Uuid, publisher: Uuid, id: u64) -> Vec<Value> {
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, id)]);
    let mut callback = push(subscriber, Some(publisher), &raw, 10);
    callback["subscription_sequence"] = json!(4);
    vec![
        exchange(
            publisher,
            1,
            "PUBLISH",
            &[b"jobs", &request(SOURCE, id)],
            b":1\r\n",
        ),
        callback,
    ]
}

#[tokio::test]
async fn rpc_subscriber_generation_uses_callback_anchor_before_first_or_last_subscription() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let older = Uuid::new_v4();
        let required = Uuid::new_v4();
        let later = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let runtime = runtime(
            temp.path(),
            &rpc_records(required, publisher, 1),
            &[subscribe(older), subscribe(required), subscribe(later)],
            lazy,
        )
        .await
        .unwrap();
        runtime.state.lock().await.active_case_id = None;
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        {
            let mut state = runtime.state.lock().await;
            assert_eq!(
                state.protocols.redis.events.matched[0].connection_id,
                required
            );
            assert_eq!(state.protocols.redis.events.matched[0].sequence, 4);
            state.active_case_id = Some("case".into());
        }
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":1\r\n"
        );
        let received = read(&mut subscriber).await;
        let frame = parse_pubsub_push(&received).unwrap().unwrap();
        assert_eq!(frame.payload, callback(TARGET, 9));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                read_redis_frame(&mut subscriber)
            )
            .await
            .is_err()
        );
        let state = runtime.state.lock().await;
        assert!(state.protocols.redis.snapshot().unsafe_events.is_empty());
        assert!(state.protocols.redis.snapshot().unmatched.is_empty());
        assert!(state.protocols.redis.snapshot().unused_case.is_empty());
        assert_eq!(state.protocols.redis.snapshot().unused_global.len(), 2);
        assert_eq!(
            state
                .protocols
                .redis
                .pubsub
                .report()
                .unwrap()
                .delivered_rpc_callbacks,
            1
        );
        task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn rpc_subscriber_generation_priority_preserves_active_case_scope() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let case_subscriber = Uuid::new_v4();
        let global_subscriber = Uuid::new_v4();
        let mut records = vec![subscribe(case_subscriber)];
        records.extend(rpc_records(global_subscriber, Uuid::new_v4(), 1));
        let runtime = runtime(temp.path(), &records, &[subscribe(global_subscriber)], lazy)
            .await
            .unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        let state = runtime.state.lock().await;
        assert_eq!(
            state.protocols.redis.events.matched[0].connection_id,
            case_subscriber
        );
        assert_eq!(
            state.protocols.redis.events.matched[0].source,
            ReplaySource::Case
        );
        task.abort();
    }
}

#[tokio::test]
async fn rpc_subscriber_generations_keep_distinct_live_connections_and_finite_callbacks() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let older = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut records = rpc_records(first, Uuid::new_v4(), 1);
        records.extend(rpc_records(second, Uuid::new_v4(), 2));
        let runtime = runtime(
            temp.path(),
            &records,
            &[subscribe(older), subscribe(first), subscribe(second)],
            lazy,
        )
        .await
        .unwrap();
        runtime.state.lock().await.active_case_id = None;
        let (mut first_client, first_task) = connect(&runtime).await;
        let (mut second_client, second_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut first_client, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        assert_eq!(
            send(&mut second_client, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        runtime.state.lock().await.active_case_id = Some("case".into());
        let (mut publisher, pub_task) = connect(&runtime).await;
        for id in [9, 10] {
            assert_eq!(
                send(&mut publisher, &[b"PUBLISH", b"jobs", &request(TARGET, id)]).await,
                b":1\r\n"
            );
        }
        for (client, id) in [(&mut first_client, 9), (&mut second_client, 10)] {
            let received = read(client).await;
            assert_eq!(
                parse_pubsub_push(&received).unwrap().unwrap().payload,
                callback(TARGET, id)
            );
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(30),
                    read_redis_frame(client)
                )
                .await
                .is_err()
            );
        }
        let state = runtime.state.lock().await;
        assert!(state.protocols.redis.snapshot().unsafe_events.is_empty());
        assert!(state.protocols.redis.snapshot().unused_case.is_empty());
        assert_eq!(
            state
                .protocols
                .redis
                .pubsub
                .report()
                .unwrap()
                .delivered_rpc_callbacks,
            2
        );
        assert!(state.protocols.redis.exchanges.iter().any(|e| {
            e.record.connection_id == older && e.status == ReplayExchangeStatus::Available
        }));
        pub_task.abort();
        first_task.abort();
        second_task.abort();
    }
}

#[tokio::test]
async fn rpc_subscriber_generation_priority_keeps_recorded_lane_predecessors() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let required = Uuid::new_v4();
        let runtime = runtime(
            temp.path(),
            &rpc_records(required, Uuid::new_v4(), 1),
            &[
                subscribe(Uuid::new_v4()),
                exchange(required, 3, "GET", &[b"before"], b"$1\r\nv\r\n"),
                subscribe(required),
            ],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, mut task) = connect(&runtime).await;
        send_unmatched(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await;
        reconnect(&runtime, &mut subscriber, &mut task).await;
        assert_eq!(
            runtime
                .state
                .lock()
                .await
                .protocols
                .redis
                .events
                .matched_count,
            0
        );
        assert_eq!(
            send(&mut subscriber, &[b"GET", b"before"]).await,
            b"$1\r\nv\r\n"
        );
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        let state = runtime.state.lock().await;
        assert_eq!(
            state.protocols.redis.events.matched[1].connection_id,
            required
        );
        task.abort();
    }
}
