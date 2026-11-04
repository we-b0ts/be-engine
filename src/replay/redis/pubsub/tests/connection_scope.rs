//! A pooled read before SUBSCRIBE does not own the later subscription socket.
use super::*;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\nlive\r\n:1\r\n";

#[tokio::test]
async fn pooled_reads_before_subscription_allow_a_dedicated_target_subscriber() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let source = Uuid::new_v4();
        let runtime = runtime(
            temp.path(),
            &[
                exchange(source, 25, "GET", &[b"online"], b"$1\r\nx\r\n"),
                exchange(source, 26, "SUBSCRIBE", &[b"live"], CONFIRMED),
                exchange(
                    source,
                    27,
                    "UNSUBSCRIBE",
                    &[b"live"],
                    b"*3\r\n$11\r\nunsubscribe\r\n$4\r\nlive\r\n:0\r\n",
                ),
            ],
            &[],
            lazy,
        )
        .await
        .unwrap();
        let (mut pool, pool_task) = connect(&runtime).await;
        let (mut subscriber, sub_task) = connect(&runtime).await;
        // A different client cannot skip the finite pre-subscription read.
        send_unmatched(&mut subscriber, &[b"SUBSCRIBE", b"live"]).await;
        let (mut subscriber, sub_task_after_reject) = connect(&runtime).await;
        assert_eq!(send(&mut pool, &[b"GET", b"online"]).await, b"$1\r\nx\r\n");
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"live"]).await,
            CONFIRMED
        );
        // Once SUBSCRIBE is admitted, its native tail stays on that client.
        send_unmatched(&mut pool, &[b"UNSUBSCRIBE", b"live"]).await;
        assert_eq!(
            send(&mut subscriber, &[b"UNSUBSCRIBE", b"live"]).await,
            b"*3\r\n$11\r\nunsubscribe\r\n$4\r\nlive\r\n:0\r\n"
        );
        let state = runtime.state.lock().await;
        assert!(state.redis.snapshot().unused_case.is_empty());
        assert_eq!(state.redis.snapshot().unmatched.len(), 2);
        pool_task.abort();
        sub_task.abort();
        sub_task_after_reject.abort();
    }
}
