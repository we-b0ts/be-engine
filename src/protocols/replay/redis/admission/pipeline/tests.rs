use super::*;
use crate::interaction::model::{InputTranscript, Protocol};
use crate::replay::{ReplayLifecycleConfig, ReplayStreamTiming, redis::append::tests::event};
use serde_json::json;
use tokio::{net::TcpListener, time::Duration};

#[tokio::test(start_paused = true)]
async fn heartbeat_tail_broadcast_replies_do_not_block_their_room_predecessors() {
    heartbeat_tail_broadcasts(true).await;
}

#[tokio::test(start_paused = true)]
async fn heartbeat_tail_broadcasts_stay_dirty_if_a_room_predecessor_is_missing() {
    heartbeat_tail_broadcasts(false).await;
}

async fn heartbeat_tail_broadcasts(complete: bool) {
    use crate::interaction::{
        model::{EndReason, WireMessage},
        observation::Observation,
        policy::InteractionPolicy,
    };
    let mut source = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    source
        .output(
            WireMessage::text(r#"0{"sid":"source","pingInterval":1000,"pingTimeout":500}"#),
            0,
        )
        .unwrap();
    source.output(WireMessage::text("2"), 1_000).unwrap();
    source.server_close(Some(1000), String::new());
    let (input, output) = source.finish(EndReason::ServerEof, 2_500, true).unwrap();
    let broadcast = |namespace, room, value| {
        json!({
            "method":"emit","event":"update","data":[value],"binary":false,
            "namespace":namespace,"room":room,"skip_sid":null,"callback":null,
            "host_id":"550e8400e29b41d4a716446655440000"
        })
        .to_string()
    };
    let frames = [
        broadcast("/chat", "user:1", 0),
        broadcast("/chat", "other:1", 0),
        broadcast("/runtime", "stream:1", 1),
        broadcast("/runtime", "stream:1", 2),
    ];
    let source = frames
        .iter()
        .enumerate()
        .map(|(i, payload)| {
            let reply = format!(":{}\r\n", 173 + i);
            event(
                i as u64 + 1,
                "PUBLISH",
                &[b"socketio", payload.as_bytes()],
                reply.as_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let (_root, runtime) = super::super::tests::runtime_with_response(
        &source,
        json!({"format":"traffic-policy/v3","rules":[]}),
        json!({"method":"GET","uri":"/socket.io/","timestamp":"2020-01-01T00:00:00Z","interaction":input}),
        json!({"status":101,"interaction":output}),
        ReplayLifecycleConfig { stream_timing: Some(ReplayStreamTiming::Fast), ..Default::default() },
    ).await;
    let (begin, _) = crate::replay::control::handle_control_request(
        serde_json::from_value(json!({"command":"input_timing_begin","case_id":"case"})).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(begin["fast_tail"]["heartbeat_timeout"], true, "{begin}");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    let mut client = RedisBufferedReader::new(client, 4096);
    for i in [2, 3, 0, 1].into_iter().take(if complete { 4 } else { 3 }) {
        let request = crate::redis::encode_array(&[b"PUBLISH", b"socketio", frames[i].as_bytes()]);
        client.inner.write_all(&request).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), read_redis_frame(&mut client))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            response.raw.as_ref(),
            format!(":{}\r\n", 173 + i).as_bytes()
        );
        if i == 3 {
            tokio::time::advance(Duration::from_secs(7)).await;
            assert_eq!(
                runtime
                    .state
                    .lock()
                    .await
                    .protocols
                    .redis
                    .snapshot()
                    .matched_count,
                0
            );
        }
    }
    drop(client);
    task.await.unwrap().unwrap();
    if !complete {
        tokio::time::advance(crate::replay::FAST_CASE_TIMEOUT).await;
        tokio::task::yield_now().await;
        let state = runtime.state.lock().await;
        let report = state.protocols.redis.snapshot();
        assert!(report.is_dirty());
        assert!(state.protocols.redis.case_has_runtime_failure("case"));
        assert_eq!(report.matched_count, 1);
        return;
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let state = runtime.state.lock().await;
            let report = state.protocols.redis.snapshot();
            if report.matched_count == 4 {
                assert!(!report.is_dirty());
                assert_eq!(
                    report
                        .matched
                        .iter()
                        .map(|row| row.sequence)
                        .collect::<Vec<_>>(),
                    [1, 2, 3, 4]
                );
                break;
            }
            drop(state);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn adjacent_socketio_publishes_admit_in_source_order_and_reply_in_resp_order() {
    let envelope = |namespace: &str| {
        json!({"method":"emit","event":"update","data":[1],"binary":false,
            "namespace":namespace,"room":null,"skip_sid":null,"callback":null,
            "host_id":"550e8400e29b41d4a716446655440000"})
        .to_string()
    };
    let earlier = envelope("/earlier");
    let later = envelope("/later");
    let mut input = InputTranscript::new(Protocol::SocketIo, Default::default());
    // Ordered business timing does not require proof that heartbeat wait can be skipped.
    input.socket_io_heartbeat = Some(Default::default());
    let (_root, runtime) = super::super::tests::runtime_with_request(
        &[
            event(1, "PUBLISH", &[b"socketio", earlier.as_bytes()], b":11\r\n"),
            event(2, "PUBLISH", &[b"socketio", later.as_bytes()], b":22\r\n"),
            event(3, "GET", &[b"next"], b"$1\r\nx\r\n"),
        ],
        json!({"format":"traffic-policy/v3","rules":[]}),
        json!({"method":"GET","uri":"/socket.io/","timestamp":"2020-01-01T00:00:00Z",
            "interaction":input}),
        ReplayLifecycleConfig {
            stream_timing: Some(ReplayStreamTiming::Fast),
            ..Default::default()
        },
    )
    .await;
    let (begin, _) = crate::replay::control::handle_control_request(
        serde_json::from_value(json!({"command":"input_timing_begin","case_id":"case"})).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(begin["ok"], true, "{begin}");
    assert_eq!(begin["ordered_fast"], true, "{begin}");
    assert!(begin["fast_tail"].is_null(), "{begin}");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    let mut client = RedisBufferedReader::new(client, 4096);
    let later_frame = crate::redis::encode_array(&[b"PUBLISH", b"socketio", later.as_bytes()]);
    client.inner.write_all(&later_frame).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .protocols
                .redis
                .events
                .request_order
                .latest(Some("case"))
                == Some(0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    // Queue the first admission's retry on ReplayState before the lookahead
    // frame arrives. Both admissions must be polled once the lock is released.
    let contention = runtime.state.lock().await;
    tokio::time::advance(Duration::from_millis(150)).await;
    tokio::task::yield_now().await;
    let mut bytes = crate::redis::encode_array(&[b"PUBLISH", b"socketio", earlier.as_bytes()]);
    bytes.extend(crate::redis::encode_array(&[b"GET", b"next"]));
    client.inner.write_all(&bytes).await.unwrap();
    tokio::task::yield_now().await;
    drop(contention);
    for expected in [b":22\r\n".as_slice(), b":11\r\n", b"$1\r\nx\r\n"] {
        let frame = tokio::time::timeout(Duration::from_secs(1), read_redis_frame(&mut client))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.raw.as_ref(), expected);
    }
    drop(client);
    task.await.unwrap().unwrap();

    let state = runtime.state.lock().await;
    let report = state.protocols.redis.snapshot();
    assert!(!report.is_dirty());
    assert!(report.unused_case.is_empty());
    assert_eq!(
        report
            .matched
            .iter()
            .map(|row| (row.sequence, row.target_event_index))
            .collect::<Vec<_>>(),
        [(1, Some(1)), (2, Some(0)), (3, Some(2))]
    );
}

#[tokio::test(start_paused = true)]
async fn socketio_call_and_two_sequential_room_broadcasts_share_one_redis_stream() {
    serial_room_broadcasts(1, true, false).await;
}

#[tokio::test(start_paused = true)]
async fn socketio_call_waits_for_two_pairs_of_room_broadcasts() {
    serial_room_broadcasts(2, true, false).await;
}

#[tokio::test(start_paused = true)]
async fn socketio_call_uses_the_effective_case_lane_after_attribution() {
    serial_room_broadcasts(1, true, true).await;
}

#[tokio::test(start_paused = true)]
async fn deferred_socketio_call_stays_failed_if_a_room_broadcast_never_arrives() {
    serial_room_broadcasts(2, false, false).await;
}

async fn serial_room_broadcasts(pairs: u64, send_last: bool, foreign_gap: bool) {
    let broadcast = |room, value| {
        json!({"method":"emit","event":"slot_update","data":[value],"binary":false,
            "namespace":"/chat","room":room,"skip_sid":null,"callback":null,
            "host_id":"550e8400e29b41d4a716446655440000"})
        .to_string()
    };
    let broadcasts = (0..pairs)
        .flat_map(|value| {
            [
                broadcast("user:1", value),
                broadcast("wework:user:1", value),
            ]
        })
        .collect::<Vec<_>>();
    let last_broadcast = 2 * pairs;
    let call_sequence = last_broadcast + if foreign_gap { 3 } else { 1 };
    let call = json!({"method":"emit","event":"sync","data":[2],"binary":false,
        "namespace":"/executor","room":"executor-sid","skip_sid":null,
        "callback":["executor-sid","/executor",1],
        "host_id":"550e8400e29b41d4a716446655440000"})
    .to_string();
    let input = InputTranscript::new(Protocol::SocketIo, Default::default());
    let mut publish_call = event(
        call_sequence,
        "PUBLISH",
        &[b"socketio", call.as_bytes()],
        b":33\r\n",
    );
    publish_call["rpc_callback_capture"] = "bounded_window".into();
    let mut source = (1..=last_broadcast)
        .zip(&broadcasts)
        .map(|(sequence, publish)| {
            let reply = format!(":{sequence}\r\n");
            event(
                sequence,
                "PUBLISH",
                &[b"socketio", publish.as_bytes()],
                reply.as_bytes(),
            )
        })
        .collect::<Vec<_>>();
    source.push(publish_call);
    let (_root, runtime) = super::super::tests::runtime_with_request(
        &source,
        json!({"format":"traffic-policy/v3","rules":[]}),
        json!({"method":"GET","uri":"/socket.io/","timestamp":"2020-01-01T00:00:00Z",
            "interaction":input}),
        ReplayLifecycleConfig {
            stream_timing: Some(ReplayStreamTiming::Fast),
            ..Default::default()
        },
    )
    .await;
    if foreign_gap {
        let mut state = runtime.state.lock().await;
        let mut targets = BTreeMap::new();
        for sequence in last_broadcast + 1..call_sequence {
            let record = serde_json::from_value(event(
                sequence,
                "PUBLISH",
                &[b"socketio", b"foreign case event"],
                b":0\r\n",
            ))
            .unwrap();
            state
                .protocols
                .redis
                .register_exchange(
                    record,
                    ReplaySource::Case,
                    Some("other-case"),
                    &mut targets,
                    &[],
                )
                .unwrap();
        }
    }
    let (begin, _) = crate::replay::control::handle_control_request(
        serde_json::from_value(json!({"command":"input_timing_begin","case_id":"case"})).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await;
    assert_eq!(begin["ordered_fast"], true, "{begin}");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    let mut client = RedisBufferedReader::new(client, 4096);
    let frame = crate::redis::encode_array(&[b"PUBLISH", b"socketio", call.as_bytes()]);
    client.inner.write_all(&frame).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(1), read_redis_frame(&mut client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reply.raw.as_ref(), b":33\r\n");
    let sent = last_broadcast - u64::from(!send_last);
    for (sequence, publish) in (1..=sent).zip(&broadcasts) {
        let frame = crate::redis::encode_array(&[b"PUBLISH", b"socketio", publish.as_bytes()]);
        client.inner.write_all(&frame).await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(1), read_redis_frame(&mut client))
            .await
            .expect("the second room is sent only after the first room's reply")
            .unwrap()
            .unwrap();
        assert_eq!(frame.raw.as_ref(), format!(":{sequence}\r\n").as_bytes());
        if sequence < last_broadcast {
            assert!(
                runtime
                    .state
                    .lock()
                    .await
                    .protocols
                    .redis
                    .snapshot()
                    .matched
                    .iter()
                    .all(|row| row.sequence != call_sequence)
            );
        }
    }
    if !send_last {
        tokio::time::sleep(Duration::from_secs(6)).await;
        drop(client);
        task.await.unwrap().unwrap();
        let state = runtime.state.lock().await;
        let report = state.protocols.redis.snapshot();
        assert!(report.is_dirty());
        assert!(state.protocols.redis.case_has_runtime_failure("case"));
        assert_eq!(
            report
                .matched
                .iter()
                .map(|row| row.sequence)
                .collect::<Vec<_>>(),
            (1..=sent).collect::<Vec<_>>()
        );
        assert!(
            report
                .unused_case
                .iter()
                .any(|row| row.sequence == last_broadcast)
        );
        return;
    }
    drop(client);
    task.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .protocols
                .redis
                .snapshot()
                .matched_count
                == (last_broadcast + 1) as usize
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    let state = runtime.state.lock().await;
    let report = state.protocols.redis.snapshot();
    assert!(!state.protocols.redis.case_is_dirty("case"));
    assert_eq!(report.unused_case.len(), if foreign_gap { 2 } else { 0 });
    assert_eq!(
        report
            .matched
            .iter()
            .map(|row| (row.sequence, row.target_event_index))
            .collect::<Vec<_>>(),
        (1..=last_broadcast)
            .map(|sequence| (sequence, Some(sequence as usize)))
            .chain([(call_sequence, Some(0))])
            .collect::<Vec<_>>()
    );
}
