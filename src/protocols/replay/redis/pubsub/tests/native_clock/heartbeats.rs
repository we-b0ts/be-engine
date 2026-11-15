//! Transport PONGs neither suppress native input nor become business ACK fences.
use super::*;

fn add_pong(root: &Path, explicit: bool, business: bool) {
    let path = root.join("case/request.json");
    let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut pong = request["interaction"]["actions"][0].clone();
    pong["sequence"] = 2.into();
    pong["offset_ms"] = 10.into();
    pong["action"]["message"]["data"] = "3".into();
    request["interaction"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(pong.clone());
    if explicit {
        request["interaction"]["socket_io_heartbeat"] =
            json!({"responses":[{"input_sequence":2,"ping_ordinal":1,"delay_ms":1}]});
    }
    if business {
        pong["sequence"] = 3.into();
        pong["offset_ms"] = 20.into();
        pong["action"]["message"]["data"] = "42/chat,0[\"join\",{}]".into();
        request["interaction"]["actions"]
            .as_array_mut()
            .unwrap()
            .push(pong);
    }
    std::fs::write(path, request.to_string()).unwrap();
}

#[tokio::test]
async fn legacy_and_explicit_heartbeats_preserve_native_delivery_and_business_ack_guards() {
    for explicit in [false, true] {
        for business in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (globals, original) = fixture(temp.path());
            add_pong(temp.path(), explicit, business);
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
            if business {
                guards::silent(&mut subscriber).await;
                assert_eq!(
                    guards::control(
                        &runtime,
                        json!({"command":"native_input_ack",
                        "case_id":CASE,"native_event":{"epoch":epoch,"acknowledged":2}})
                    )
                    .await["ok"],
                    false,
                    "PONG cannot be acknowledged as a business event"
                );
                guards::silent(&mut subscriber).await;
                assert_eq!(
                    guards::control(
                        &runtime,
                        json!({"command":"native_input_ack",
                        "case_id":CASE,"native_event":{"epoch":epoch,"acknowledged":3}})
                    )
                    .await["ok"],
                    true
                );
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), read(&mut subscriber))
                    .await
                    .expect("a recorded PONG must not disable the native notification window"),
                original
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
                1
            );
            task.abort();
        }
    }
}

#[tokio::test]
async fn client_ping_and_business_dependent_pong_do_not_gain_native_input_permission() {
    for data in ["2", "3"] {
        let temp = tempfile::tempdir().unwrap();
        let (globals, _) = fixture(temp.path());
        add_pong(temp.path(), false, false);
        let path = temp.path().join("case/request.json");
        let mut request: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        request["interaction"]["actions"][1]["action"]["message"]["data"] = data.into();
        if data == "3" {
            request["interaction"]["actions"][1]["after"] = json!([1]);
        }
        std::fs::write(path, request.to_string()).unwrap();
        let runtime = recording::ambient_runtime(temp.path(), &[], &globals, true)
            .await
            .unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        assert_eq!(
            guards::control(&runtime, json!({"command":"request_begin","case_id":CASE})).await["ok"],
            true
        );
        let observer = guards::control(
            &runtime,
            json!({"command":"native_event_begin","case_id":CASE}),
        )
        .await;
        assert_eq!(observer["enabled"], false);
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
}
