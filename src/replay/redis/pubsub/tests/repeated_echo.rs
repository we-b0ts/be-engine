//! Repeated bytes need finite Source PUBLISH clocks, never an arbitrary first slot.
use super::*;
use std::time::Duration;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

fn broadcast(host: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&request(host, 1)).unwrap();
    value["callback"] = Value::Null;
    serde_json::to_vec(&value).unwrap()
}

async fn fixture(root: &Path, lazy: bool, scenario: &str) -> Arc<ReplayRuntime> {
    let source = broadcast(SOURCE);
    let publisher = Uuid::new_v4();
    let sub = Uuid::new_v4();
    let mut first = exchange(publisher, 1, "PUBLISH", &[b"jobs", &source], b":1\r\n");
    let mut second = exchange(publisher, 2, "PUBLISH", &[b"jobs", &source], b":1\r\n");
    first["duration_ms"] = 2.into();
    second["duration_ms"] = 2.into();
    first["request_started_at"] = json!("2026-10-28T00:00:01.000Z");
    first["timestamp"] = json!("2026-10-28T00:00:01.002Z");
    second["request_started_at"] = json!("2026-10-28T00:00:11.000Z");
    second["timestamp"] = json!("2026-10-28T00:00:11.002Z");
    let raw = crate::redis::encode_array(&[b"message", b"jobs", &source]);
    let mut echo_one = push(sub, None, &raw, 1_003);
    let mut echo_two = push(sub, None, &raw, 11_003);
    echo_one["timestamp"] = json!("2026-10-28T00:00:01.003Z");
    echo_two["timestamp"] = json!("2026-10-28T00:00:11.003Z");
    match scenario {
        "valid" => {}
        "overlap" => second["request_started_at"] = json!("2026-10-28T00:00:01.001Z"),
        "missing-publish-clock" => {
            first.as_object_mut().unwrap().remove("timestamp");
        }
        "missing-notification-clock" => {
            echo_two.as_object_mut().unwrap().remove("timestamp");
        }
        "two-in-one-interval" => {
            echo_two["timestamp"] = json!("2026-10-28T00:00:01.004Z");
            echo_two["duration_ms"] = 1_004.into();
        }
        _ => unreachable!(),
    }
    runtime(
        root,
        &[first, second],
        &[
            exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], CONFIRMED),
            echo_one,
            echo_two,
        ],
        lazy,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn repeated_broadcasts_claim_their_own_source_interval_once_with_live_payloads() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let runtime = fixture(temp.path(), lazy, "valid").await;
        let (mut subscriber, sub_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            CONFIRMED
        );
        let (mut client, task) = connect(&runtime).await;
        let actual = broadcast(TARGET);
        for expected_count in 1..=2 {
            assert_eq!(
                send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
                b":1\r\n"
            );
            let frame = read(&mut subscriber).await;
            assert_eq!(parse_pubsub_push(&frame).unwrap().unwrap().payload, actual);
            // Delivery, rather than queue admission, consumes the finite slot.
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if runtime
                        .state
                        .lock()
                        .await
                        .redis
                        .pubsub
                        .report()
                        .unwrap()
                        .delivered_pushes
                        == expected_count
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        send_unmatched(&mut client, &[b"PUBLISH", b"jobs", &actual]).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(40), read_redis_frame(&mut subscriber))
                .await
                .is_err()
        );
        let state = runtime.state.lock().await;
        assert!(state.redis.pubsub.unused(ReplaySource::Startup).is_empty());
        assert!(state.redis.snapshot().unused_case.is_empty());
        task.abort();
        sub_task.abort();
    }
}

#[tokio::test]
async fn repeated_broadcasts_reject_missing_clocks_overlaps_and_duplicate_interval_slots() {
    for lazy in [false, true] {
        for scenario in [
            "overlap",
            "missing-publish-clock",
            "missing-notification-clock",
            "two-in-one-interval",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let runtime = fixture(temp.path(), lazy, scenario).await;
            let (mut subscriber, sub_task) = connect(&runtime).await;
            assert_eq!(
                send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
                CONFIRMED
            );
            let (mut client, task) = connect(&runtime).await;
            // The PUBLISH response can precede the echo failure; it cannot
            // authorize a fabricated notification or successful consumption.
            let _ = send(&mut client, &[b"PUBLISH", b"jobs", &broadcast(TARGET)]).await;
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let failed = !runtime
                        .state
                        .lock()
                        .await
                        .redis
                        .snapshot()
                        .unsafe_events
                        .is_empty();
                    if failed {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(40), read_redis_frame(&mut subscriber))
                    .await
                    .is_err(),
                "{scenario}"
            );
            let state = runtime.state.lock().await;
            assert_eq!(
                state.redis.pubsub.report().unwrap().delivered_pushes,
                0,
                "{scenario}"
            );
            assert_eq!(
                state.redis.pubsub.unused(ReplaySource::Startup).len(),
                2,
                "{scenario}"
            );
            task.abort();
            sub_task.abort();
        }
    }
}
