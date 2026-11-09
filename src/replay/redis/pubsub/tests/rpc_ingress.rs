//! Real remote requests retain their original slot and require a live observed SID.
use super::*;
use std::time::Duration;

const SOURCE_SID: &str = "sourceSID0123456789a";
const TARGET_SID: &str = "targetSID0123456";
const START: &str = "2020-01-01T00:00:00Z";
const SUBSCRIBED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
mod causal_order;
mod wire_barrier;

fn request_bytes() -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&request(SOURCE, 17)).unwrap();
    value["room"] = SOURCE_SID.into();
    value["callback"][0] = SOURCE_SID.into();
    serde_json::to_vec(&value).unwrap()
}

fn reply(sid: &str) -> Value {
    json!({"method":"callback", "host_id":SOURCE, "sid":sid, "namespace":"/rpc", "id":17,
        "args":[{"result":"ok"}]})
}

fn fixture(root: &Path) -> (Vec<Value>, Vec<Value>) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    std::fs::write(
        root.join("case/request.json"),
        json!({"method":"GET", "uri":"/socket.io/",
        "timestamp":START, "interaction":{"protocol":"socket_io"}})
        .to_string(),
    )
    .unwrap();
    std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
    std::fs::write(root.join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v3\njson:\n  fields:\n    /socket_id: {kind: identity, formats: [string]}\n").unwrap();
    let publisher = Uuid::new_v4();
    let subscriber = Uuid::new_v4();
    let mut set = exchange(
        publisher,
        1,
        "SET",
        &[
            b"online",
            &serde_json::to_vec(&json!({"socket_id":SOURCE_SID})).unwrap(),
        ],
        b"+OK\r\n",
    );
    set["response_kind"] = "simple_string".into();
    set["timestamp"] = START.into();
    let mut callback = exchange(
        publisher,
        2,
        "PUBLISH",
        &[b"jobs", &serde_json::to_vec(&reply(SOURCE_SID)).unwrap()],
        b":1\r\n",
    );
    callback["timestamp"] = "2020-01-01T00:00:00.080Z".into();
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &request_bytes()]);
    let mut incoming = push(subscriber, None, &raw, 600_000);
    incoming["timestamp"] = "2020-01-01T00:00:00.040Z".into();
    (
        vec![set, callback],
        vec![
            exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], SUBSCRIBED),
            incoming,
        ],
    )
}

#[tokio::test]
async fn remote_rpc_uses_case_clock_observed_sid_and_one_original_notification() {
    for lazy in [false, true] {
        for source_error in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (mut cases, mut globals) = fixture(temp.path());
            let response: &[u8] = if source_error {
                b"-ERR recorded publish rejection\r\n"
            } else {
                b":1\r\n"
            };
            if source_error {
                cases[1]["response_kind"] = "error".into();
                cases[1]["response"] = capture(response);
            }
            // A different Global message keeps its own subscription timer and bytes.
            let raw = crate::redis::encode_array(&[b"message", b"jobs", b"ordinary-global"]);
            let sub = Uuid::parse_str(globals[0]["connection_id"].as_str().unwrap()).unwrap();
            globals.push(push(sub, None, &raw, 60));
            let runtime = runtime(temp.path(), &cases, &globals, lazy).await.unwrap();
            let (mut subscriber, sub_task) = connect(&runtime).await;
            let (mut client, mut client_task) = connect(&runtime).await;
            assert_eq!(
                send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
                SUBSCRIBED
            );
            // Neither time alone nor a guessed callback creates a session or consumes a reply.
            send_unmatched(
                &mut client,
                &[
                    b"PUBLISH",
                    b"jobs",
                    &serde_json::to_vec(&reply(TARGET_SID)).unwrap(),
                ],
            )
            .await;
            reconnect(&runtime, &mut client, &mut client_task).await;
            assert_eq!(read(&mut subscriber).await, raw);
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
            // An admitted subscription and a known SID cannot start an HTTP Case.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), read_redis_frame(&mut subscriber))
                    .await
                    .is_err()
            );
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
            // Original subscription time is ten minutes; the live Case admits the
            // original request at its 40 ms offset, after a real SID observation.
            let raw = read(&mut subscriber).await;
            let frame = parse_pubsub_push(&raw).unwrap().unwrap();
            let actual: Value = serde_json::from_slice(&frame.payload).unwrap();
            assert_eq!(actual["room"], TARGET_SID);
            assert_eq!(actual["callback"], json!([TARGET_SID, "/rpc", 17]));
            assert_eq!(actual["host_id"], SOURCE);
            assert_eq!(actual["data"], json!([{"argv":["pwd"]}]));
            for (pointer, value) in [
                ("/sid", json!("another-session")),
                ("/host_id", json!(TARGET)),
                ("/namespace", json!("/another")),
                ("/id", json!(18)),
                ("/args/0/result", json!("changed")),
            ] {
                let mut changed = reply(TARGET_SID);
                *changed.pointer_mut(pointer).unwrap() = value;
                send_unmatched(
                    &mut client,
                    &[b"PUBLISH", b"jobs", &serde_json::to_vec(&changed).unwrap()],
                )
                .await;
                reconnect(&runtime, &mut client, &mut client_task).await;
            }
            let actual = serde_json::to_vec(&reply(TARGET_SID)).unwrap();
            assert_eq!(
                send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
                response
            );
            send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &actual]).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), read_redis_frame(&mut subscriber))
                    .await
                    .is_err()
            );
            let state = runtime.state.lock().await;
            assert!(state.redis.snapshot().unused_case.is_empty());
            assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 2);
            drop(state);
            sub_task.abort();
            client_task.abort();
        }
    }
}

#[tokio::test]
async fn a_remote_callback_and_a_local_call_share_one_redis_pipeline() {
    use crate::interaction::model::{InputTranscript, Protocol};

    let temp = tempfile::tempdir().unwrap();
    let (mut cases, globals) = fixture(temp.path());
    let input = InputTranscript::new(Protocol::SocketIo, Default::default());
    std::fs::write(
        temp.path().join("case/request.json"),
        json!({"method":"GET", "uri":"/socket.io/", "timestamp":START, "interaction":input})
            .to_string(),
    )
    .unwrap();
    let mut call: Value = serde_json::from_slice(&request_bytes()).unwrap();
    call["host_id"] = TARGET.into();
    call["event"] = "device:sync_capabilities".into();
    call["callback"][2] = 18.into();
    let mut publish = exchange(
        Uuid::parse_str(cases[1]["connection_id"].as_str().unwrap()).unwrap(),
        3,
        "PUBLISH",
        &[b"jobs", &serde_json::to_vec(&call).unwrap()],
        b":2\r\n",
    );
    publish["rpc_callback_capture"] = "bounded_window".into();
    publish["timestamp"] = "2020-01-01T00:00:00.100Z".into();
    cases.push(publish);
    for record in &mut cases {
        record["request_started_at"] = record["timestamp"].clone();
    }
    let runtime = runtime_with_timing(
        temp.path(),
        &cases,
        &globals,
        false,
        Some(crate::ReplayStreamTiming::Fast),
    )
    .await
    .unwrap();
    runtime
        .state
        .lock()
        .await
        .redis
        .request_contracts
        .request_begin("case")
        .unwrap();
    let (begin, _) = crate::replay::control::handle_control_request(
        serde_json::from_value(json!({"command":"input_timing_begin","case_id":"case"})).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(begin["ordered_fast"], true, "{begin}");
    let (mut subscriber, subscriber_task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    let (mut client, client_task) = connect(&runtime).await;
    let online = serde_json::to_vec(&json!({"socket_id":TARGET_SID})).unwrap();
    assert_eq!(
        send(&mut client, &[b"SET", b"online", &online]).await,
        b"+OK\r\n"
    );
    let raw = read(&mut subscriber).await;
    let push = parse_pubsub_push(&raw).unwrap().unwrap();
    let incoming: Value = serde_json::from_slice(&push.payload).unwrap();
    assert_eq!(incoming["callback"], json!([TARGET_SID, "/rpc", 17]));

    call["room"] = TARGET_SID.into();
    call["callback"][0] = TARGET_SID.into();
    let call = serde_json::to_vec(&call).unwrap();
    let callback = serde_json::to_vec(&reply(TARGET_SID)).unwrap();
    let mut frames = crate::redis::encode_array(&[b"PUBLISH", b"jobs", &call]);
    frames.extend(crate::redis::encode_array(&[
        b"PUBLISH", b"jobs", &callback,
    ]));
    client.inner.write_all(&frames).await.unwrap();
    assert_eq!(read(&mut client).await, b":2\r\n");
    assert_eq!(read(&mut client).await, b":1\r\n");
    drop(client);
    client_task.await.unwrap().unwrap();
    let state = runtime.state.lock().await;
    let report = state.redis.snapshot();
    assert!(!report.is_dirty());
    assert_eq!(
        report
            .matched
            .iter()
            .filter(|row| row.command == "PUBLISH")
            .map(|row| (row.sequence, row.target_event_index))
            .collect::<Vec<_>>(),
        [(2, Some(3)), (3, Some(2))]
    );
    subscriber_task.abort();
}

#[tokio::test]
async fn delayed_sid_observation_preserves_ingress_order_when_replies_were_out_of_order() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (mut cases, mut globals) = fixture(temp.path());
        let mut later_reply = cases[1].clone();
        later_reply["sequence"] = 3.into();
        later_reply["timestamp"] = "2020-01-01T00:00:00.090Z".into();
        let mut first_reply = reply(SOURCE_SID);
        first_reply["id"] = 18.into();
        cases[1]["args"][1] = capture(&serde_json::to_vec(&first_reply).unwrap());
        cases.push(later_reply);
        let sub = Uuid::parse_str(globals[0]["connection_id"].as_str().unwrap()).unwrap();
        let mut second_request: Value = serde_json::from_slice(&request_bytes()).unwrap();
        second_request["callback"][2] = 18.into();
        let raw = crate::redis::encode_array(&[
            b"message",
            b"jobs",
            &serde_json::to_vec(&second_request).unwrap(),
        ]);
        let mut incoming = push(sub, None, &raw, 600_010);
        incoming["timestamp"] = "2020-01-01T00:00:00.050Z".into();
        globals.push(incoming);
        let runtime = runtime(temp.path(), &cases, &globals, lazy).await.unwrap();
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
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, client_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
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
        for id in [17, 18] {
            let raw = read(&mut subscriber).await;
            let frame = parse_pubsub_push(&raw).unwrap().unwrap();
            let value: Value = serde_json::from_slice(&frame.payload).unwrap();
            assert_eq!(value["callback"], json!([TARGET_SID, "/rpc", id]));
        }
        for id in [18, 17] {
            let mut value = reply(TARGET_SID);
            value["id"] = id.into();
            assert_eq!(
                send(
                    &mut client,
                    &[b"PUBLISH", b"jobs", &serde_json::to_vec(&value).unwrap()]
                )
                .await,
                b":1\r\n"
            );
        }
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

#[tokio::test]
async fn remote_rpc_missing_ambiguous_or_inconsistent_source_evidence_fails_before_admission() {
    for lazy in [false, true] {
        for invalid in [
            "missing",
            "duplicate",
            "clock",
            "before-case",
            "after-reply",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (cases, mut globals) = fixture(temp.path());
            match invalid {
                "missing" => {
                    globals.pop();
                }
                "duplicate" => globals.push(globals[1].clone()),
                "clock" => {
                    globals[1].as_object_mut().unwrap().remove("timestamp");
                }
                "before-case" => globals[1]["timestamp"] = "2019-12-31T23:59:59Z".into(),
                "after-reply" => globals[1]["timestamp"] = "2020-01-01T00:00:01Z".into(),
                _ => unreachable!(),
            }
            let error = runtime(temp.path(), &cases, &globals, lazy)
                .await
                .err()
                .expect(invalid);
            assert!(
                format!("{error:#}").contains("remote Socket.IO"),
                "{invalid}: {error:#}"
            );
        }
    }
}

#[tokio::test]
async fn ordinary_callback_payload_without_socketio_case_metadata_keeps_strict_matching() {
    let temp = tempfile::tempdir().unwrap();
    let payload = serde_json::to_vec(&reply(SOURCE_SID)).unwrap();
    let runtime = runtime(
        temp.path(),
        &[exchange(
            Uuid::new_v4(),
            1,
            "PUBLISH",
            &[b"jobs", &payload],
            b":1\r\n",
        )],
        &[],
        true,
    )
    .await
    .unwrap();
    let (mut client, mut task) = connect(&runtime).await;
    send_unmatched(
        &mut client,
        &[
            b"PUBLISH",
            b"jobs",
            &serde_json::to_vec(&reply(TARGET_SID)).unwrap(),
        ],
    )
    .await;
    reconnect(&runtime, &mut client, &mut task).await;
    assert_eq!(
        send(&mut client, &[b"PUBLISH", b"jobs", &payload]).await,
        b":1\r\n"
    );
    task.abort();
}
