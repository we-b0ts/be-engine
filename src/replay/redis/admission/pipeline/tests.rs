use super::*;
use crate::interaction::model::{InputTranscript, Protocol};
use crate::replay::{ReplayLifecycleConfig, ReplayStreamTiming, redis::append::tests::event};
use serde_json::json;
use tokio::{net::TcpListener, time::Duration};

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
    let report = state.redis.snapshot();
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
    serial_room_broadcasts(true).await;
}

#[tokio::test(start_paused = true)]
async fn deferred_socketio_call_stays_failed_if_a_room_broadcast_never_arrives() {
    serial_room_broadcasts(false).await;
}

async fn serial_room_broadcasts(send_second: bool) {
    let broadcast = |room| {
        json!({"method":"emit","event":"slot_update","data":[1],"binary":false,
            "namespace":"/chat","room":room,"skip_sid":null,"callback":null,
            "host_id":"550e8400e29b41d4a716446655440000"})
        .to_string()
    };
    let first = broadcast("user:1");
    let second = broadcast("wework:user:1");
    let call = json!({"method":"emit","event":"sync","data":[2],"binary":false,
        "namespace":"/executor","room":"executor-sid","skip_sid":null,
        "callback":["executor-sid","/executor",1],
        "host_id":"550e8400e29b41d4a716446655440000"})
    .to_string();
    let input = InputTranscript::new(Protocol::SocketIo, Default::default());
    let mut publish_call = event(3, "PUBLISH", &[b"socketio", call.as_bytes()], b":33\r\n");
    publish_call["rpc_callback_capture"] = "bounded_window".into();
    let (_root, runtime) = super::super::tests::runtime_with_request(
        &[
            event(1, "PUBLISH", &[b"socketio", first.as_bytes()], b":11\r\n"),
            event(2, "PUBLISH", &[b"socketio", second.as_bytes()], b":22\r\n"),
            publish_call,
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
    for publish in [&call, &first] {
        let frame = crate::redis::encode_array(&[b"PUBLISH", b"socketio", publish.as_bytes()]);
        client.inner.write_all(&frame).await.unwrap();
    }
    for expected in [b":33\r\n".as_slice(), b":11\r\n"] {
        let frame = tokio::time::timeout(Duration::from_secs(1), read_redis_frame(&mut client))
            .await
            .expect("the second room is sent only after the first room's reply")
            .unwrap()
            .unwrap();
        assert_eq!(frame.raw.as_ref(), expected);
    }
    if !send_second {
        tokio::time::sleep(Duration::from_secs(6)).await;
        drop(client);
        task.await.unwrap().unwrap();
        let state = runtime.state.lock().await;
        let report = state.redis.snapshot();
        assert!(report.is_dirty());
        assert!(state.redis.case_has_runtime_failure("case"));
        assert_eq!(
            report
                .matched
                .iter()
                .map(|row| row.sequence)
                .collect::<Vec<_>>(),
            [1]
        );
        assert!(report.unused_case.iter().any(|row| row.sequence == 2));
        return;
    }
    let frame = crate::redis::encode_array(&[b"PUBLISH", b"socketio", second.as_bytes()]);
    client.inner.write_all(&frame).await.unwrap();
    let reply = read_redis_frame(&mut client).await.unwrap().unwrap();
    assert_eq!(reply.raw.as_ref(), b":22\r\n");
    drop(client);
    task.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.state.lock().await.redis.snapshot().matched_count == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    let state = runtime.state.lock().await;
    let report = state.redis.snapshot();
    assert!(!report.is_dirty());
    assert!(report.unused_case.is_empty());
    assert_eq!(
        report
            .matched
            .iter()
            .map(|row| (row.sequence, row.target_event_index))
            .collect::<Vec<_>>(),
        [(1, Some(1)), (2, Some(2)), (3, Some(0))]
    );
}
