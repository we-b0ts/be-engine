use super::*;

pub(super) async fn control(runtime: &Arc<ReplayRuntime>, value: Value) -> Value {
    crate::replay::control::handle_control_request(
        serde_json::from_value(value).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await
    .0
}

pub(super) async fn silent(reader: &mut RedisBufferedReader<TcpStream>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(35), read_redis_frame(reader))
            .await
            .is_err()
    );
}

pub(super) async fn begin(runtime: &Arc<ReplayRuntime>) -> Value {
    assert_eq!(
        control(runtime, json!({"command":"request_begin","case_id":"case"})).await["ok"],
        true
    );
    let response = control(
        runtime,
        json!({"command":"native_event_begin","case_id":"case"}),
    )
    .await;
    assert_eq!(response["enabled"], true);
    response["epoch"].clone()
}

pub(super) async fn connected(
    runtime: &Arc<ReplayRuntime>,
    epoch: Value,
    namespace: &str,
) -> Value {
    control(
        runtime,
        json!({"command":"native_connected","case_id":"case",
        "native_event":{"epoch":epoch,"namespace":namespace}}),
    )
    .await
}

#[tokio::test]
async fn original_slot_waits_for_actual_namespace_and_rejects_wrong_epochs() {
    let temp = tempfile::tempdir().unwrap();
    let (mut globals, original) = fixture(temp.path());
    globals[1]["duration_ms"] = 0.into();
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    silent(&mut subscriber).await;
    let epoch = begin(&runtime).await;
    silent(&mut subscriber).await;
    let wrong = serde_json::from_value::<chrono::DateTime<chrono::Utc>>(epoch.clone()).unwrap()
        - chrono::TimeDelta::milliseconds(1);
    assert_eq!(
        connected(&runtime, json!(wrong), "/chat").await["ok"],
        false
    );
    assert_eq!(
        connected(&runtime, epoch.clone(), "/other").await["ok"],
        false
    );
    assert_eq!(
        control(
            &runtime,
            json!({"command":"native_connected","case_id":"other",
        "native_event":{"epoch":epoch,"namespace":"/chat"}})
        )
        .await["ok"],
        false
    );
    silent(&mut subscriber).await;
    assert_eq!(connected(&runtime, epoch, "/chat").await["ok"], true);
    assert_eq!(read(&mut subscriber).await, original);
    silent(&mut subscriber).await;
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
        1
    );
    task.abort();
}

#[tokio::test]
async fn ambiguous_unselected_windows_and_unsupported_programs_keep_slots_unused() {
    for mode in [
        "overlap",
        "no_clock",
        "request_clock",
        "no_boundary",
        "excluded_sid",
        "clock_inversion",
        "unclean",
        "outside",
        "active_program",
        "terminal_program",
        "reused_ack_ids",
        "same_millisecond",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, original) = fixture(temp.path());
        globals[1]["duration_ms"] = 0.into();
        match mode {
            "overlap" => {
                let other = temp.path().join("unselected");
                std::fs::create_dir_all(&other).unwrap();
                for file in [
                    "request.json",
                    "expected-response.json",
                    "dependencies.jsonl",
                ] {
                    if file == "dependencies.jsonl" {
                        std::fs::write(other.join(file), "").unwrap();
                    } else {
                        std::fs::copy(temp.path().join("case").join(file), other.join(file))
                            .unwrap();
                    }
                }
            }
            "no_clock" => {
                globals[1]["timestamp"] = Value::Null;
            }
            "request_clock" => {
                let path = temp.path().join("case/request.json");
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value["timestamp"] = Value::Null;
                std::fs::write(path, value.to_string()).unwrap();
            }
            "no_boundary" => {
                std::fs::remove_file(temp.path().join("recording-run.json")).unwrap();
            }
            "excluded_sid" => {
                let frame = parse_pubsub_push(&original).unwrap().unwrap();
                let mut value: Value = serde_json::from_slice(&frame.payload).unwrap();
                value["skip_sid"] = "unproven-source-sid".into();
                globals[1]["response"] = capture(&crate::redis::encode_array(&[
                    b"message",
                    b"jobs",
                    &serde_json::to_vec(&value).unwrap(),
                ]));
            }
            "clock_inversion" => {
                let mut later = globals[1].clone();
                later["timestamp"] = "2020-01-01T00:10:00.020Z".into();
                globals.push(later);
            }
            "outside" => {
                globals[1]["timestamp"] = "2020-01-01T00:09:59Z".into();
            }
            "unclean" => {
                let path = temp.path().join("case/expected-response.json");
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value["interaction"]["end"]["clean"] = false.into();
                std::fs::write(path, value.to_string()).unwrap();
            }
            "active_program" => {
                let path = temp.path().join("case/request.json");
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                let mut second = value["interaction"]["actions"][0].clone();
                second["sequence"] = 2.into();
                second["offset_ms"] = 20.into();
                second["action"]["message"]["data"] = "42/chat,[\"work\",{}]".into();
                value["interaction"]["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push(second);
                std::fs::write(path, value.to_string()).unwrap();
            }
            "terminal_program" | "reused_ack_ids" | "same_millisecond" => {
                let path = temp.path().join("case/request.json");
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                let mut second = value["interaction"]["actions"][0].clone();
                second["sequence"] = 2.into();
                second["offset_ms"] = if mode == "same_millisecond" { 40 } else { 20 }.into();
                second["action"]["message"]["data"] = "42/chat,0[\"work\",{}]".into();
                value["interaction"]["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push(second.clone());
                if mode == "reused_ack_ids" {
                    second["sequence"] = 3.into();
                    second["offset_ms"] = 30.into();
                    value["interaction"]["actions"]
                        .as_array_mut()
                        .unwrap()
                        .push(second);
                }
                if mode == "terminal_program" {
                    value["interaction"]["policy"]["completion"] = json!([{"namespace":"/chat","event":"work","completion":{"kind":"terminal_event","event":"finished","require_ack":true}}]);
                }
                std::fs::write(path, value.to_string()).unwrap();
            }
            _ => unreachable!(),
        }
        let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        assert_eq!(
            control(
                &runtime,
                json!({"command":"request_begin","case_id":"case"})
            )
            .await["ok"],
            true
        );
        assert_eq!(
            control(
                &runtime,
                json!({"command":"native_event_begin","case_id":"case"})
            )
            .await["enabled"],
            false,
            "{mode}"
        );
        silent(&mut subscriber).await;
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
            0,
            "{mode}"
        );
        task.abort();
    }
}

#[tokio::test]
async fn unrelated_timers_and_original_self_echoes_retain_their_owners() {
    for echo in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (mut globals, original) = fixture(temp.path());
        let sub = Uuid::parse_str(globals[0]["connection_id"].as_str().unwrap()).unwrap();
        let mut cases = Vec::new();
        let mut published = None;
        if echo {
            let payload = parse_pubsub_push(&original).unwrap().unwrap().payload;
            cases.push(exchange(
                Uuid::new_v4(),
                1,
                "PUBLISH",
                &[b"jobs", &payload],
                b":1\r\n",
            ));
            published = Some(payload);
            globals[1]["duration_ms"] = 0.into();
        } else {
            let raw = crate::redis::encode_array(&[b"message", b"jobs", b"ordinary bytes"]);
            globals.push(push(sub, None, &raw, 10));
        }
        let runtime = runtime(temp.path(), &cases, &globals, true).await.unwrap();
        let (mut subscriber, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            SUBSCRIBED
        );
        if let Some(payload) = published {
            silent(&mut subscriber).await;
            let (mut publisher, pub_task) = connect(&runtime).await;
            assert_eq!(
                send(&mut publisher, &[b"PUBLISH", b"jobs", &payload]).await,
                b":1\r\n"
            );
            assert_eq!(read(&mut subscriber).await, original);
            pub_task.abort();
        } else {
            assert_eq!(
                read(&mut subscriber).await,
                crate::redis::encode_array(&[b"message", b"jobs", b"ordinary bytes"])
            );
        }
        silent(&mut subscriber).await;
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
            1
        );
        task.abort();
    }
}

#[tokio::test]
async fn queued_delivery_cannot_cross_a_case_or_request_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let (globals, _) = fixture(temp.path());
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let epoch: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(begin(&runtime).await).unwrap();
    let mut state = runtime.state.lock().await;
    let delivery = Delivery {
        push: PushId::Indexed { lane: 0, index: 0 },
        bytes: vec![],
        matched: None,
        case_id: Some("case".into()),
        request_epoch: Some(epoch),
    };
    assert!(delivery.case_is_current(&state));
    state.redis.pubsub.native_clock.begin_case("case");
    state
        .redis
        .pubsub
        .native_clock
        .request_begin("case", epoch + chrono::TimeDelta::milliseconds(1))
        .unwrap();
    assert!(!delivery.case_is_current(&state));
    state.active_case_id = Some("other".into());
    assert!(!delivery.case_is_current(&state));
    state.active_case_id = Some("case".into());
    state.target_session_stopped = true;
    assert!(!delivery.case_is_current(&state));
}
