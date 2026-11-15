//! A subscription anchor identifies a lane, never its individual notifications.
use super::*;
use std::collections::BTreeSet;

const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

#[tokio::test]
async fn unused_case_notifications_keep_each_physical_source_identity_after_delivery() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let subscription = Uuid::new_v4();
        let raw = crate::redis::encode_array(&[b"message", b"jobs", b"stream chunk"]);
        let mut records = vec![exchange(
            subscription,
            1,
            "SUBSCRIBE",
            &[b"jobs"],
            CONFIRMED,
        )];
        let ids: Vec<_> = (0..184).map(|_| Uuid::new_v4()).collect();
        for (index, id) in ids.iter().enumerate() {
            let mut notification = push(
                subscription,
                None,
                &raw,
                if index == 0 { 20 } else { 60_000 },
            );
            let mut capture = crate::dependency::observation::fixture_capture("case");
            capture.exchange_id = *id;
            notification["capture"] = serde_json::to_value(capture).unwrap();
            records.push(notification);
        }
        let runtime = runtime(temp.path(), &records, &[], lazy).await.unwrap();
        {
            let state = runtime.state.lock().await;
            let report = state.protocols.redis.snapshot();
            let notifications: Vec<_> = report
                .unused_case
                .iter()
                .filter(|entry| entry.command == "PUBSUB_PUSH")
                .collect();
            assert_eq!(notifications.len(), 184);
            assert_eq!(
                notifications
                    .iter()
                    .map(|entry| entry.source_exchange_id.unwrap())
                    .collect::<BTreeSet<_>>(),
                ids.iter().copied().collect()
            );
            let subscription = report
                .unused_case
                .iter()
                .find(|entry| entry.command == "SUBSCRIBE")
                .unwrap();
            assert!(
                serde_json::to_value(subscription)
                    .unwrap()
                    .get("source_exchange_id")
                    .is_none()
            );
        }
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await, CONFIRMED);
        assert_eq!(read(&mut client).await, raw);
        let state = runtime.state.lock().await;
        let report = state.protocols.redis.snapshot();
        assert_eq!(report.unused_case.len(), 183);
        assert_eq!(
            report
                .unused_case
                .iter()
                .map(|entry| entry.source_exchange_id.unwrap())
                .collect::<BTreeSet<_>>(),
            ids[1..].iter().copied().collect()
        );
        assert_eq!(
            state
                .protocols
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
