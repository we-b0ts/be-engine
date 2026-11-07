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
    let (_root, runtime) = super::super::tests::runtime_with_request(
        &[
            event(1, "PUBLISH", &[b"socketio", earlier.as_bytes()], b":11\r\n"),
            event(2, "PUBLISH", &[b"socketio", later.as_bytes()], b":22\r\n"),
            event(3, "GET", &[b"next"], b"$1\r\nx\r\n"),
        ],
        json!({"format":"traffic-policy/v3","rules":[]}),
        json!({"method":"GET","uri":"/socket.io/","timestamp":"2020-01-01T00:00:00Z",
            "interaction":InputTranscript::new(Protocol::SocketIo, Default::default())}),
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
