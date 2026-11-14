//! Native delivery stops at an unacknowledged input until a proven later checkpoint.
use super::*;

fn program(root: &Path, close: bool) {
    let path = root.join("case/request.json");
    let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let action = |sequence, offset_ms, action| InputAction {
        sequence,
        offset_ms,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action,
    };
    let actions = request["interaction"]["actions"].as_array_mut().unwrap();
    actions.push(
        serde_json::to_value(action(
            2,
            10,
            InputActionKind::Message {
                message: WireMessage::text("42/chat,0[\"join\",{}]"),
            },
        ))
        .unwrap(),
    );
    actions.push(
        serde_json::to_value(action(
            3,
            200,
            if close {
                InputActionKind::Close {
                    code: None,
                    reason: String::new(),
                }
            } else {
                InputActionKind::Message {
                    message: WireMessage::text("42/chat,[\"leave\",{}]"),
                }
            },
        ))
        .unwrap(),
    );
    if !close {
        actions.push(
            serde_json::to_value(action(
                4,
                300,
                InputActionKind::Message {
                    message: WireMessage::text("42/chat,1[\"join\",{}]"),
                },
            ))
            .unwrap(),
        );
    }
    std::fs::write(path, request.to_string()).unwrap();
}

#[tokio::test]
async fn later_unacknowledged_input_preserves_only_the_proven_notification_prefix() {
    for lazy in [false, true] {
        for close in [false, true] {
            for at in [40, 200, 250] {
                let temp = tempfile::tempdir().unwrap();
                let (mut globals, original) = fixture(temp.path());
                program(temp.path(), close);
                globals[1]["timestamp"] = format!("2020-01-01T00:10:00.{at:03}Z").into();
                let runtime = recording::ambient_runtime(temp.path(), &[], &globals, lazy)
                    .await
                    .unwrap();
                let (mut subscriber, task) = connect(&runtime).await;
                assert_eq!(
                    send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
                    SUBSCRIBED
                );
                if at < 200 {
                    let epoch = guards::begin(&runtime).await;
                    assert_eq!(
                        guards::connected(&runtime, epoch.clone(), "/chat").await["ok"],
                        true
                    );
                    guards::silent(&mut subscriber).await;
                    assert_eq!(
                        guards::control(
                            &runtime,
                            json!({"command":"native_input_ack",
                        "case_id":CASE,"native_event":{"epoch":epoch,"acknowledged":2}})
                        )
                        .await["ok"],
                        true
                    );
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(1), read(&mut subscriber))
                            .await
                            .unwrap(),
                        original
                    );
                    if !close {
                        assert_eq!(
                            guards::control(
                                &runtime,
                                json!({"command":"native_input_ack",
                            "case_id":CASE,"native_event":{"epoch":epoch,"acknowledged":4}})
                            )
                            .await["ok"],
                            true,
                            "a later real ACK remains valid without reopening the prefix"
                        );
                    }
                } else {
                    guards::control(&runtime, json!({"command":"request_begin","case_id":CASE}))
                        .await;
                    assert_eq!(
                        guards::control(
                            &runtime,
                            json!({"command":"native_event_begin","case_id":CASE})
                        )
                        .await["enabled"],
                        false,
                        "notifications at or after an unacknowledged input stay unadmitted"
                    );
                }
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
                    usize::from(at < 200)
                );
                task.abort();
            }
        }
    }
}

#[tokio::test]
async fn delayed_ack_cannot_deliver_a_prefix_notification_after_its_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let (globals, _) = fixture(temp.path());
    program(temp.path(), false);
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
        guards::connected(&runtime, epoch.clone(), "/chat").await["ok"],
        true
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        guards::control(
            &runtime,
            json!({"command":"native_input_ack",
        "case_id":CASE,"native_event":{"epoch":epoch,"acknowledged":2}})
        )
        .await["ok"],
        true
    );
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
async fn later_source_ack_reopens_delivery_only_after_the_matching_live_ack() {
    for (offset, source_acks, deliver) in [
        (315, vec!["43/chat,1[true]"], false),
        (320, vec!["43/chat,1[true]"], false),
        (340, vec!["43/chat,1[true]"], true),
        (340, vec!["43/other,1[true]"], false),
        (340, vec!["43/chat,1[true]", "43/chat,1[true]"], false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, original) = fixture(temp.path());
        program(temp.path(), false);
        let earlier = globals[1].clone();
        globals[1]["timestamp"] = format!("2020-01-01T00:10:00.{offset:03}Z").into();
        if deliver {
            globals.insert(1, earlier);
        }
        let path = temp.path().join("case/expected-response.json");
        let mut response: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        response["interaction"]["events"] = json!(
            source_acks
                .iter()
                .enumerate()
                .map(|(index, &ack)| json!({
                    "sequence":index+1,"offset_ms":320+index,
                    "message":{"kind":"text","data":ack}
                }))
                .collect::<Vec<_>>()
        );
        std::fs::write(path, response.to_string()).unwrap();
        let runtime = recording::ambient_runtime(temp.path(), &[], &globals, true)
            .await
            .unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        if deliver {
            let epoch = guards::begin(&runtime).await;
            assert_eq!(
                guards::connected(&runtime, epoch.clone(), "/chat").await["ok"],
                true
            );
            let ack = |sequence| {
                json!({"command":"native_input_ack","case_id":CASE,
                "native_event":{"epoch":epoch,"acknowledged":sequence}})
            };
            tokio::time::sleep(Duration::from_millis(360)).await;
            assert_eq!(guards::control(&runtime, ack(2)).await["ok"], true);
            guards::silent(&mut subscriber).await;
            assert_eq!(guards::control(&runtime, ack(4)).await["ok"], true);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), read(&mut subscriber))
                    .await
                    .unwrap(),
                original
            );
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
        } else {
            let state = runtime.state.lock().await;
            assert!(
                !state
                    .protocols
                    .redis
                    .pubsub
                    .native_clock
                    .needs_observer(CASE)
            );
        }
        task.abort();
    }
}
