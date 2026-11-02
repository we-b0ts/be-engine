//! Ordinary Case-owned notification inputs retain finite native delivery.
use super::*;
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
