//! Real WS observations and real Redis consumption jointly gate early remote RPCs.
use super::*;
use crate::interaction::{
    model::{AckReference, InputAction, InputActionKind, InputTranscript, Protocol, WireMessage},
    policy::InteractionPolicy,
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

fn preceding(cases: &mut Vec<Value>) -> Value {
    let mut call: Value = serde_json::from_slice(&request_bytes()).unwrap();
    call["host_id"] = TARGET.into();
    call["event"] = "device:sync_capabilities".into();
    call["callback"][2] = 1.into();
    let mut publish = exchange(
        Uuid::parse_str(cases[0]["connection_id"].as_str().unwrap()).unwrap(),
        2,
        "PUBLISH",
        &[b"jobs", &serde_json::to_vec(&call).unwrap()],
        b":1\r\n",
    );
    publish["rpc_callback_capture"] = "bounded_window".into();
    publish["timestamp"] = "2020-01-01T00:00:00.020Z".into();
    cases[1]["sequence"] = 3.into();
    cases.insert(1, publish);
    call
}

async fn admit(runtime: &Arc<ReplayRuntime>) -> chrono::DateTime<chrono::Utc> {
    let mut state = runtime.state.lock().await;
    state.redis.request_contracts.request_begin("case").unwrap();
    let epoch = state
        .redis
        .request_contracts
        .request_times("case")
        .target
        .unwrap();
    assert!(state.redis.native_events_begin("case", epoch));
    epoch
}

async fn online(client: &mut RedisBufferedReader<TcpStream>) {
    assert_eq!(
        send(
            client,
            &[
                b"SET",
                b"online",
                &serde_json::to_vec(&json!({"socket_id":TARGET_SID})).unwrap()
            ]
        )
        .await,
        b"+OK\r\n"
    );
}

fn event(namespace: &str, name: &str, ordinal: u64) -> crate::interaction::replay::NativeEvent {
    crate::interaction::replay::NativeEvent {
        namespace: namespace.into(),
        event: name.into(),
        ordinal,
    }
}

#[tokio::test]
async fn ordinary_case_without_ingress_does_not_require_an_rpc_clock_or_policy() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = runtime(temp.path(), &[], &[], true).await.unwrap();
    assert!(
        runtime
            .state
            .lock()
            .await
            .redis
            .request_contracts
            .request_times("case")
            .target
            .is_none()
    );
    let request =
        serde_json::from_value(json!({"command":"native_event_begin", "case_id":"case"})).unwrap();
    let (response, stop) =
        crate::replay::control::handle_control_request(request, runtime.state.clone(), None, None)
            .await;
    assert_eq!(response, json!({"ok":true,"enabled":false}));
    assert!(!stop);
}

#[tokio::test]
async fn causal_ingress_needs_both_prefix_consumption_and_actual_event_in_current_epoch() {
    for lazy in [false, true] {
        for event_first in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (mut cases, globals) = fixture(temp.path());
            let call = preceding(&mut cases);
            let runtime = runtime(temp.path(), &cases, &globals, lazy).await.unwrap();
            let epoch = admit(&runtime).await;
            let (mut subscriber, sub_task) = connect(&runtime).await;
            let (mut client, client_task) = connect(&runtime).await;
            assert_eq!(
                send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
                SUBSCRIBED
            );
            online(&mut client).await;
            let proof = event("/rpc", "device:sync_capabilities", 1);
            {
                let mut state = runtime.state.lock().await;
                assert!(
                    state
                        .redis
                        .observe_native_event("other", epoch, &proof)
                        .is_err()
                );
                assert!(
                    state
                        .redis
                        .observe_native_event(
                            "case",
                            epoch + chrono::TimeDelta::milliseconds(1),
                            &proof
                        )
                        .is_err()
                );
                assert!(
                    state
                        .redis
                        .observe_native_event(
                            "case",
                            epoch,
                            &event("/rpc", "device:sync_capabilities", 2)
                        )
                        .is_err()
                );
                // An unrelated actual event never proves the prerequisite.
                state
                    .redis
                    .observe_native_event(
                        "case",
                        epoch,
                        &event("/other", "device:sync_capabilities", 1),
                    )
                    .unwrap();
            }
            if event_first {
                runtime
                    .state
                    .lock()
                    .await
                    .redis
                    .observe_native_event("case", epoch, &proof)
                    .unwrap();
            } else {
                assert_eq!(
                    send(
                        &mut client,
                        &[b"PUBLISH", b"jobs", &serde_json::to_vec(&call).unwrap()]
                    )
                    .await,
                    b":1\r\n"
                );
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(90), read_redis_frame(&mut subscriber))
                    .await
                    .is_err(),
                "time, SID and only one half of the causal proof must not release RPC"
            );
            if event_first {
                assert_eq!(
                    send(
                        &mut client,
                        &[b"PUBLISH", b"jobs", &serde_json::to_vec(&call).unwrap()]
                    )
                    .await,
                    b":1\r\n"
                );
            } else {
                runtime
                    .state
                    .lock()
                    .await
                    .redis
                    .observe_native_event("case", epoch, &proof)
                    .unwrap();
            }
            let raw = read(&mut subscriber).await;
            assert_eq!(parse_pubsub_push(&raw).unwrap().unwrap().channel, b"jobs");
            assert!(
                runtime
                    .state
                    .lock()
                    .await
                    .redis
                    .observe_native_event("case", epoch, &proof)
                    .is_err(),
                "duplicate observation cannot be counted twice"
            );
            assert_eq!(
                send(
                    &mut client,
                    &[
                        b"PUBLISH",
                        b"jobs",
                        &serde_json::to_vec(&reply(TARGET_SID)).unwrap()
                    ]
                )
                .await,
                b":1\r\n"
            );
            assert!(
                runtime
                    .state
                    .lock()
                    .await
                    .redis
                    .snapshot()
                    .unused_case
                    .is_empty()
            );
            sub_task.abort();
            client_task.abort();
        }
    }
}

fn input_program() -> InputTranscript {
    let mut input = InputTranscript::new(
        Protocol::SocketIo,
        InteractionPolicy {
            business_idle_ms: 1000,
            max_duration_ms: 3000,
            request_timeout_ms: 3000,
            cleanup_timeout_ms: 500,
            ..Default::default()
        },
    );
    input.actions = [
        ("40/rpc,", None),
        ("43/rpc,2[{\"plugins\":[],\"success\":false}]", Some(1)),
        ("43/rpc,3[{\"workspaces\":[],\"success\":true}]", Some(2)),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (message, ordinal))| InputAction {
        sequence: i as u64 + 1,
        offset_ms: i as u64 * 20,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: ordinal.map(|server_event_ordinal| AckReference {
            namespace: "/rpc".into(),
            server_event_ordinal,
        }),
        action: InputActionKind::Message {
            message: WireMessage::text(message),
        },
    })
    .collect();
    input
}

fn assert_ack(message: Message, id: u64, data: Value) {
    let packet =
        crate::interaction::socketio::decode_engine_io_text(&message.into_text().unwrap(), 1024)
            .unwrap();
    let crate::interaction::socketio::EngineIoPacket::Message(packet) = packet else {
        panic!("expected actual Socket.IO ACK");
    };
    assert_eq!(packet.kind, crate::interaction::socketio::SocketIoKind::Ack);
    assert_eq!(packet.namespace, "/rpc");
    assert_eq!(packet.id, Some(id));
    assert_eq!(packet.data, Some(data));
}

#[tokio::test]
async fn slow_target_prepare_preserves_recorded_ack_payloads_across_live_ws_and_redis() {
    for (lazy, fast) in [(false, false), (true, false), (true, true)] {
        let temp = tempfile::tempdir().unwrap();
        let (mut cases, mut globals) = fixture(temp.path());
        let call = preceding(&mut cases);
        let mut reply_value = reply(SOURCE_SID);
        reply_value["args"] = json!([{"workspaces":[],"success":true}]);
        cases[2]["args"][1] = capture(&serde_json::to_vec(&reply_value).unwrap());
        let mut input = input_program();
        if fast {
            input.policy.max_duration_ms = 15_000;
            input.policy.request_timeout_ms = 15_000;
            input.actions[2].offset_ms = 12_000;
            globals[1]["timestamp"] = "2020-01-01T00:00:11.990Z".into();
            cases[0]["request_started_at"] = START.into();
            cases[1]["request_started_at"] = "2020-01-01T00:00:00.010Z".into();
            cases[2]["request_started_at"] = "2020-01-01T00:00:12.005Z".into();
            cases[2]["timestamp"] = "2020-01-01T00:00:12.010Z".into();
        }
        // Runtime timing preparation and execution must see the same complete
        // original input program, rather than a protocol-only fixture hint.
        let request = json!({"method":"GET","uri":"/socket.io/?EIO=4&transport=websocket",
            "timestamp":START,"headers":{},"body":capture(b""),"interaction":input});
        std::fs::write(temp.path().join("case/request.json"), request.to_string()).unwrap();
        let runtime = runtime(temp.path(), &cases, &globals, lazy).await.unwrap();
        // This is the same private control path used by RecordedHttpClient.
        let socket_path = temp.path().join("control.sock");
        let session = temp.path().join("session.json");
        std::fs::write(&session, json!({"control_socket":socket_path}).to_string()).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let state = runtime.state.clone();
        let control = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                crate::replay::control::handle_control_stream(stream, state.clone(), None, None)
                    .await
                    .unwrap();
            }
        });
        {
            let mut state = runtime.state.lock().await;
            if fast {
                state.stream_timing = Some(crate::replay::ReplayStreamTiming::Fast);
                state.stream_interval_cap_ms = 5;
            }
            state.redis.request_contracts.request_begin("case").unwrap();
        }
        let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = ws_listener.local_addr().unwrap();
        let target_runtime = runtime.clone();
        let target = tokio::spawn(async move {
            let (stream, _) = ws_listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket.send(Message::Text("0{\"sid\":\"engine-sid\",\"upgrades\":[],\"pingInterval\":10000,\"pingTimeout\":10000}".into())).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "40/rpc,"
            );
            socket
                .send(Message::Text(
                    format!("40/rpc,{{\"sid\":\"{TARGET_SID}\"}}").into(),
                ))
                .await
                .unwrap();
            let (mut subscriber, sub_task) = connect(&target_runtime).await;
            let (mut client, client_task) = connect(&target_runtime).await;
            assert_eq!(
                send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
                SUBSCRIBED
            );
            online(&mut client).await;
            assert_eq!(
                send(
                    &mut client,
                    &[b"PUBLISH", b"jobs", &serde_json::to_vec(&call).unwrap()]
                )
                .await,
                b":1\r\n"
            );
            // Target's PUBLISH has finished but its local native emission is slow.
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    read_redis_frame(&mut subscriber)
                )
                .await
                .is_err()
            );
            socket
                .send(Message::Text(
                    "42/rpc,71[\"device:sync_capabilities\",{}]".into(),
                ))
                .await
                .unwrap();
            assert_ack(
                socket.next().await.unwrap().unwrap(),
                71,
                json!([{"plugins":[],"success":false}]),
            );
            let raw = read(&mut subscriber).await;
            let incoming: Value =
                serde_json::from_slice(&parse_pubsub_push(&raw).unwrap().unwrap().payload).unwrap();
            assert_eq!(incoming["room"], TARGET_SID);
            socket
                .send(Message::Text("42/rpc,72[\"runtime:rpc\",{}]".into()))
                .await
                .unwrap();
            assert_ack(
                socket.next().await.unwrap().unwrap(),
                72,
                json!([{"workspaces":[],"success":true}]),
            );
            reply_value["sid"] = TARGET_SID.into();
            assert_eq!(
                send(
                    &mut client,
                    &[
                        b"PUBLISH",
                        b"jobs",
                        &serde_json::to_vec(&reply_value).unwrap()
                    ]
                )
                .await,
                b":1\r\n"
            );
            socket.close(None).await.unwrap();
            sub_task.abort();
            client_task.abort();
        });
        let client = crate::recorded_request::RecordedHttpClient::new(
            format!("http://{address}"),
            Duration::from_secs(3),
            1024 * 1024,
        )
        .with_input_registration(&session, "case");
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            client.send_bytes(&serde_json::to_vec(&request).unwrap(), "causal-input"),
        )
        .await
        .expect("the original 12-second ingress offset must compress in fast mode")
        .unwrap();
        assert!(response.interaction.unwrap().end.clean);
        target.await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.redis.snapshot().unused_case.is_empty());
        assert!(state.redis.snapshot().unmatched.is_empty());
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
        control.abort();
    }
}
