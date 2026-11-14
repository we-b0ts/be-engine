//! Unattributed inbound facts are candidates, never process-ownership claims.
use super::*;

#[tokio::test]
async fn ambient_native_input_delivers_without_admitting_unknown_outgoing_commands() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, original) = fixture(temp.path());
        let mut unknown = exchange(
            Uuid::new_v4(),
            1,
            "SET",
            &[b"unowned", b"value"],
            b"+OK\r\n",
        );
        unknown["fixture_unattributed"] = true.into();
        globals.push(unknown);
        let runtime = recording::ambient_runtime(temp.path(), &[], &globals, lazy)
            .await
            .unwrap();
        {
            let state = runtime.state.lock().await;
            assert!(
                !state
                    .protocols
                    .redis
                    .exchanges
                    .iter()
                    .any(|e| e.record.native.command == "SET")
            );
            assert_eq!(state.protocols.redis.pubsub.indexed.total, 1);
            assert_eq!(
                state.protocols.redis.pubsub.indexed.lanes[0].source_kind,
                ReplaySource::Unattributed
            );
            assert!(!ReplaySource::Unattributed.is_run_owned());
            assert_eq!(
                state
                    .batch_scope
                    .as_ref()
                    .unwrap()
                    .inventory
                    .unattributed_dependencies,
                2
            );
        }
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        guards::silent(&mut subscriber).await;
        let epoch = guards::begin(&runtime).await;
        guards::silent(&mut subscriber).await;
        assert_eq!(
            guards::connected(&runtime, epoch, "/chat").await["ok"],
            true
        );
        assert_eq!(read(&mut subscriber).await, original);
        guards::silent(&mut subscriber).await;
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
                .batch_scope
                .as_ref()
                .unwrap()
                .inventory
                .unattributed_dependencies,
            2
        );
        assert!(
            !state
                .snapshot_report()
                .batch_reconciliation
                .unwrap()
                .dependency_inventory_verified
        );
        task.abort();
    }
}

#[tokio::test]
async fn ambient_input_has_no_subscription_age_fallback_without_a_proven_window() {
    let temp = tempfile::tempdir().unwrap();
    let (mut globals, original) = fixture(temp.path());
    let frame = parse_pubsub_push(&original).unwrap().unwrap();
    let mut payload: Value = serde_json::from_slice(&frame.payload).unwrap();
    payload["namespace"] = "/foreign".into();
    globals[1]["response"] = capture(&crate::redis::encode_array(&[
        b"message",
        b"jobs",
        &serde_json::to_vec(&payload).unwrap(),
    ]));
    globals[1]["duration_ms"] = 0.into();
    let runtime = recording::ambient_runtime(temp.path(), &[], &globals, true)
        .await
        .unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    guards::silent(&mut subscriber).await;
    let response =
        guards::control(&runtime, json!({"command":"request_begin","case_id":CASE})).await;
    assert_eq!(response["ok"], true);
    guards::silent(&mut subscriber).await;
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
        0
    );
    task.abort();
}

#[tokio::test]
async fn original_order_survives_a_subscription_split_between_owned_and_ambient_views() {
    let temp = tempfile::tempdir().unwrap();
    let (mut globals, first) = fixture(temp.path());
    let frame = parse_pubsub_push(&first).unwrap().unwrap();
    let mut payload: Value = serde_json::from_slice(&frame.payload).unwrap();
    payload["data"][0]["value"] = 8.into();
    let second =
        crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(&payload).unwrap()]);
    let mut owned = globals[1].clone();
    owned["response"] = capture(&second);
    owned["timestamp"] = "2020-01-01T00:10:00.070Z".into();
    owned["fixture_process_owned"] = true.into();
    globals.push(owned);
    let runtime = recording::ambient_runtime(temp.path(), &[], &globals, true)
        .await
        .unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    let epoch = guards::begin(&runtime).await;
    assert_eq!(
        guards::connected(&runtime, epoch, "/chat").await["ok"],
        true
    );
    assert_eq!(read(&mut subscriber).await, first);
    assert_eq!(read(&mut subscriber).await, second);
    guards::silent(&mut subscriber).await;
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
        2
    );
    task.abort();
}
