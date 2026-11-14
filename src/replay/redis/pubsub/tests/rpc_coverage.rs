use super::*;

fn bounded_publisher(publisher: Uuid, id: u64) -> Value {
    let mut value = exchange(
        publisher,
        id,
        "PUBLISH",
        &[b"jobs", &request(SOURCE, id)],
        b":1\r\n",
    );
    value["rpc_callback_capture"] = "bounded_window".into();
    value
}

#[tokio::test]
async fn bounded_window_without_callback_consumes_only_the_publish_and_preserves_id_bindings() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let runtime = runtime(
            temp.path(),
            &[
                bounded_publisher(publisher, 1),
                bounded_publisher(publisher, 2),
            ],
            &[exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed)],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        let (mut publisher, mut pub_task) = connect(&runtime).await;
        let mut changed: Value = serde_json::from_slice(&request(TARGET, 9)).unwrap();
        changed["event"] = "different:event".into();
        send_unmatched(
            &mut publisher,
            &[b"PUBLISH", b"jobs", &serde_json::to_vec(&changed).unwrap()],
        )
        .await;
        reconnect(&runtime, &mut publisher, &mut pub_task).await;
        assert_eq!(
            send(&mut publisher, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":1\r\n"
        );
        // An absent callback does not waive bijective protocol identity binding.
        send_unmatched(&mut publisher, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await;
        reconnect(&runtime, &mut publisher, &mut pub_task).await;
        send_unmatched(
            &mut publisher,
            &[
                b"PUBLISH",
                b"jobs",
                &request(&Uuid::new_v4().simple().to_string(), 10),
            ],
        )
        .await;
        reconnect(&runtime, &mut publisher, &mut pub_task).await;
        assert_eq!(
            send(&mut publisher, &[b"PUBLISH", b"jobs", &request(TARGET, 10)]).await,
            b":1\r\n"
        );
        send_unmatched(&mut publisher, &[b"PUBLISH", b"jobs", &request(TARGET, 11)]).await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                read_redis_frame(&mut subscriber)
            )
            .await
            .is_err(),
            "the engine must not manufacture an RPC callback"
        );
        assert!(
            runtime
                .state
                .lock()
                .await
                .protocols
                .redis
                .snapshot()
                .unused_case
                .is_empty()
        );
        pub_task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn late_global_callback_links_only_its_original_publish_and_is_delivered_once() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
        let mut notification = push(sub, Some(publisher), &raw, 50);
        notification["rpc_request"]["case_id"] = "case".into();
        let runtime = runtime(
            temp.path(),
            &[bounded_publisher(publisher, 1)],
            &[
                exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed),
                notification,
            ],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, pub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":1\r\n"
        );
        {
            let mut state = runtime.state.lock().await;
            assert!(
                state.protocols.redis.snapshot().unused_case.is_empty(),
                "completed PUBLISH must not wait for a late callback"
            );
            state.active_case_id = None;
        }
        let delivered = read(&mut subscriber).await;
        let payload = parse_pubsub_push(&delivered).unwrap().unwrap().payload;
        let (identity, _) = rpc::callback(&payload).unwrap().unwrap();
        assert_eq!(identity.host, TARGET);
        assert_eq!(identity.id, 9);
        send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 10)]).await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
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
                .delivered_rpc_callbacks,
            1
        );
        assert!(
            state
                .protocols
                .redis
                .pubsub
                .unused(ReplaySource::Startup)
                .is_empty()
        );
        assert_eq!(
            state.protocols.redis.snapshot().matched_count,
            2,
            "callback must not consume its publisher twice"
        );
        pub_task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn late_global_callback_rejects_wrong_scope_missing_publisher_and_duplicate_refs() {
    for mode in [
        "wrong_case",
        "wrong_sequence",
        "missing_publisher",
        "duplicate",
        "duplicate_publish",
        "legacy_publisher",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
        let mut notification = push(sub, Some(publisher), &raw, 10);
        notification["rpc_request"]["case_id"] = if mode == "wrong_case" {
            "other-case"
        } else {
            "case"
        }
        .into();
        if mode == "wrong_sequence" {
            notification["rpc_request"]["sequence"] = 2.into();
        }
        let mut record = bounded_publisher(publisher, 1);
        if mode == "legacy_publisher" {
            record
                .as_object_mut()
                .unwrap()
                .remove("rpc_callback_capture");
        }
        let cases = if mode == "missing_publisher" {
            vec![]
        } else if mode == "duplicate_publish" {
            vec![record.clone(), record]
        } else {
            vec![record]
        };
        let mut globals = vec![exchange(
            sub,
            1,
            "SUBSCRIBE",
            &[b"jobs"],
            b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n",
        )];
        globals.push(notification.clone());
        if mode == "duplicate" {
            globals.push(notification);
        }
        assert!(
            runtime(temp.path(), &cases, &globals, false).await.is_err(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn global_rpc_started_during_an_api_delivers_once_after_the_active_case_changes() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let sub = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
        let runtime = runtime(
            temp.path(),
            &[],
            &[
                exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmed),
                bounded_publisher(publisher, 1),
                push(sub, Some(publisher), &raw, 50),
            ],
            lazy,
        )
        .await
        .unwrap();
        assert!(runtime.state.lock().await.active_case_id.is_some());
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, pub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
            b":1\r\n"
        );
        {
            let mut state = runtime.state.lock().await;
            assert_eq!(
                state
                    .protocols
                    .redis
                    .exchanges
                    .iter()
                    .filter(|exchange| exchange.record.native.command == "PUBLISH"
                        && exchange.status.is_consumed())
                    .count(),
                1
            );
            state.active_case_id = Some("another-api".into());
        }
        let delivered = read(&mut subscriber).await;
        let payload = parse_pubsub_push(&delivered).unwrap().unwrap().payload;
        assert_eq!(rpc::callback(&payload).unwrap().unwrap().0.id, 9);
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
        assert!(
            state
                .protocols
                .redis
                .pubsub
                .unused(ReplaySource::Startup)
                .is_empty()
        );
        assert_eq!(state.protocols.redis.snapshot().matched_count, 2);
        pub_task.abort();
        sub_task.abort();
    }
}
