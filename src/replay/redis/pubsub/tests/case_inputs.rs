//! Ordinary Case-owned notification inputs retain finite native delivery.
use super::*;
use crate::replay::ReplayStreamTiming;
use std::os::fd::AsRawFd;
use std::time::Duration;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

#[tokio::test]
async fn ordinary_case_notifications_are_delivered_once_over_the_real_subscription() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let subscription = Uuid::new_v4();
        let raw = crate::redis::encode_array(&[b"message", b"jobs", b"stream chunk"]);
        let runtime = runtime(
            temp.path(),
            &[
                exchange(subscription, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
                push(subscription, None, &raw, 20),
            ],
            &[],
            lazy,
        )
        .await
        .unwrap();
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
        assert!(
            runtime
                .state
                .lock()
                .await
                .redis
                .pubsub
                .case_is_dirty("case")
        );
        assert_eq!(read(&mut client).await, raw);
        {
            let state = runtime.state.lock().await;
            assert!(!state.redis.pubsub.case_is_dirty("case"));
            assert!(state.redis.snapshot().unused_case.is_empty());
            assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
            assert!(!state.redis.pubsub.has_case_delivery());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(40), read_redis_frame(&mut client))
                .await
                .is_err()
        );
        task.abort();
    }
}

#[tokio::test]
async fn ordinary_notification_cannot_be_delivered_into_a_later_case() {
    let temp = tempfile::tempdir().unwrap();
    let subscription = Uuid::new_v4();
    let raw = crate::redis::encode_array(&[b"message", b"jobs", b"old case input"]);
    let runtime = runtime(
        temp.path(),
        &[
            exchange(subscription, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
            push(subscription, None, &raw, 30),
        ],
        &[],
        false,
    )
    .await
    .unwrap();
    let (mut client, task) = connect(&runtime).await;
    assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
    runtime.state.lock().await.active_case_id = Some("later-case".into());
    assert!(
        tokio::time::timeout(Duration::from_millis(80), read_redis_frame(&mut client))
            .await
            .is_err()
    );
    let state = runtime.state.lock().await;
    assert!(state.redis.pubsub.case_is_dirty("case"));
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
    assert!(!state.redis.pubsub.has_case_delivery());
    task.abort();
}

#[test]
fn fast_notification_gaps_cap_each_adjacent_source_interval() {
    let offsets = [8_000, 9_000, 9_003, 60_000];
    for (cap, expected) in [(5, [5, 5, 3, 5]), (0, [0, 0, 0, 0]), (20, [20, 20, 3, 20])] {
        let mut previous = 0;
        let actual = offsets.map(|current| {
            let gap = super::super::notifications::fast_gap_ms(previous, current, cap);
            previous = current;
            gap
        });
        assert_eq!(actual, expected);
    }
    assert_eq!(super::super::notifications::fast_gap_ms(20, 10, 5), 0);
}

async fn notification_runtime(
    root: &Path,
    records: &[Value],
    lazy: bool,
    timing: Option<ReplayStreamTiming>,
) -> Arc<ReplayRuntime> {
    std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    std::fs::create_dir_all(root.join("case")).unwrap();
    std::fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        r#"{"format":"traffic-policy/v3","rules":[]}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("case/request.json"),
        json!({"method":"POST","uri":"/api/v1/responses",
            "timestamp":"2020-01-01T00:00:00Z"})
        .to_string(),
    )
    .unwrap();
    std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
    let runtime = runtime(root, records, &[], lazy).await.unwrap();
    {
        let mut state = runtime.state.lock().await;
        state.stream_timing = timing;
        state.redis.request_contracts.request_begin("case").unwrap();
    }
    runtime
}

#[tokio::test]
async fn fast_case_notifications_cross_long_source_intervals_in_order_once() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let subscription = Uuid::new_v4();
        let messages: Vec<_> = (0..4)
            .map(|index| {
                crate::redis::encode_array(&[b"message", b"jobs", index.to_string().as_bytes()])
            })
            .collect();
        let mut records = vec![exchange(
            subscription,
            1,
            "SUBSCRIBE",
            &[b"jobs"],
            CONFIRMED,
        )];
        records.extend(
            messages
                .iter()
                .enumerate()
                .map(|(index, raw)| push(subscription, None, raw, (index as u64 + 1) * 60_000)),
        );
        let runtime =
            notification_runtime(temp.path(), &records, lazy, Some(ReplayStreamTiming::Fast)).await;
        let (mut client, task) = connect(&runtime).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
            for raw in messages {
                assert_eq!(read(&mut client).await, raw);
            }
        })
        .await
        .expect("fast notification timing must not wait through recorded minutes");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), read_redis_frame(&mut client))
                .await
                .is_err()
        );
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 4);
        assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 0);
        assert!(state.redis.snapshot().unused_case.is_empty());
        assert!(!state.redis.pubsub.has_case_delivery());
        task.abort();
    }
}

#[tokio::test]
async fn default_and_recorded_notification_timing_keep_source_subscription_delay() {
    for timing in [None, Some(ReplayStreamTiming::Recorded)] {
        let temp = tempfile::tempdir().unwrap();
        let subscription = Uuid::new_v4();
        let raw = crate::redis::encode_array(&[b"message", b"jobs", b"recorded input"]);
        let runtime = notification_runtime(
            temp.path(),
            &[
                exchange(subscription, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
                push(subscription, None, &raw, 150),
            ],
            false,
            timing,
        )
        .await;
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
        assert!(
            tokio::time::timeout(Duration::from_millis(35), read_redis_frame(&mut client))
                .await
                .is_err(),
            "{timing:?} must keep the ordinary notification's Source delay"
        );
        assert_eq!(read(&mut client).await, raw);
        task.abort();
    }
}

#[tokio::test]
async fn zero_interval_cap_drains_more_than_a_queue_of_finite_notifications() {
    let temp = tempfile::tempdir().unwrap();
    let subscription = Uuid::new_v4();
    let messages: Vec<_> = (0..300)
        .map(|index| {
            crate::redis::encode_array(&[b"message", b"jobs", index.to_string().as_bytes()])
        })
        .collect();
    let mut records = vec![exchange(
        subscription,
        1,
        "SUBSCRIBE",
        &[b"jobs"],
        CONFIRMED,
    )];
    records.extend(
        messages
            .iter()
            .enumerate()
            .map(|(index, raw)| push(subscription, None, raw, (index as u64 + 1) * 60_000)),
    );
    let runtime =
        notification_runtime(temp.path(), &records, false, Some(ReplayStreamTiming::Fast)).await;
    runtime.state.lock().await.stream_interval_cap_ms = 0;
    let (mut client, task) = connect(&runtime).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
        for raw in messages {
            assert_eq!(read(&mut client).await, raw);
        }
    })
    .await
    .expect("a zero cap must drain the finite lane without Source delays");
    let state = runtime.state.lock().await;
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 300);
    assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 0);
    assert!(state.redis.snapshot().unused_case.is_empty());
    task.abort();
}

fn small_socket_buffer(stream: &TcpStream, option: libc::c_int) {
    let size: libc::c_int = 16 * 1024;
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&size).cast(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

async fn backpressured_notifications(
    root: &Path,
) -> (
    Arc<ReplayRuntime>,
    RedisBufferedReader<TcpStream>,
    tokio::task::JoinHandle<Result<()>>,
    Vec<u8>,
) {
    let subscription = Uuid::new_v4();
    // Fixed small socket windows exercise write_all without a huge recording.
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &vec![b'x'; 256 * 1024]]);
    let later = crate::redis::encode_array(&[b"message", b"jobs", b"later input"]);
    let runtime = notification_runtime(
        root,
        &[
            exchange(subscription, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
            push(subscription, None, &raw, 60_000),
            push(subscription, None, &later, 120_000),
        ],
        false,
        Some(ReplayStreamTiming::Fast),
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    small_socket_buffer(&stream, libc::SO_RCVBUF);
    small_socket_buffer(&server, libc::SO_SNDBUF);
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
    let mut client = RedisBufferedReader::new(stream, 1024 * 1024);
    assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime.state.lock().await.redis.pubsub.has_case_delivery() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fast input must enter the real native delivery path");
    tokio::time::sleep(Duration::from_millis(35)).await;
    {
        let state = runtime.state.lock().await;
        assert!(state.redis.pubsub.has_case_delivery());
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
        assert_eq!(
            state.redis.pubsub.pushes[0].status,
            ReplayExchangeStatus::Responding
        );
        assert_eq!(
            state.redis.pubsub.pushes[1].status,
            ReplayExchangeStatus::Available
        );
    }
    (runtime, client, task, raw)
}

#[tokio::test]
async fn fast_notifications_wait_for_actual_wire_progress_under_backpressure() {
    let temp = tempfile::tempdir().unwrap();
    let (runtime, mut client, task, raw) = backpressured_notifications(temp.path()).await;
    assert_eq!(read(&mut client).await, raw);
    let later = crate::redis::encode_array(&[b"message", b"jobs", b"later input"]);
    assert_eq!(read(&mut client).await, later);
    let state = runtime.state.lock().await;
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 2);
    assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 0);
    assert!(!state.redis.pubsub.has_case_delivery());
    assert!(state.redis.snapshot().unused_case.is_empty());
    task.abort();
}

#[tokio::test]
async fn fast_notification_wire_completion_respects_case_request_epoch_and_stop() {
    for boundary in ["case", "request_epoch", "target_stop"] {
        let temp = tempfile::tempdir().unwrap();
        let (runtime, mut client, task, raw) = backpressured_notifications(temp.path()).await;
        {
            let mut state = runtime.state.lock().await;
            match boundary {
                "case" => state.active_case_id = Some("later-case".into()),
                "request_epoch" => {
                    let epoch = state
                        .redis
                        .request_contracts
                        .request_times("case")
                        .target
                        .unwrap();
                    state
                        .redis
                        .request_contracts
                        .restore_request_clock_for_test(
                            "case",
                            epoch + chrono::TimeDelta::milliseconds(1),
                        );
                }
                "target_stop" => state.target_session_stopped = true,
                _ => unreachable!(),
            }
        }
        // Already admitted bytes can finish writing; they cannot commit a
        // successful delivery or release the next input in a different scope.
        assert_eq!(read(&mut client).await, raw);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_redis_frame(&mut client))
                .await
                .is_err(),
            "{boundary} must prevent the later input"
        );
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
        assert!(state.redis.pubsub.case_is_dirty("case"));
        assert!(!state.redis.pubsub.has_case_delivery());
        assert_eq!(
            state.redis.pubsub.pushes[0].status,
            ReplayExchangeStatus::Failed
        );
        assert_eq!(
            state.redis.pubsub.pushes[1].status,
            ReplayExchangeStatus::Available
        );
        task.abort();
    }
}
