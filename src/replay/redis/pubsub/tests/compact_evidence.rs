use super::*;

#[tokio::test]
async fn runtime_finalization_keeps_global_exemption_and_actual_delivery_in_compact_evidence() {
    for lazy in [false, true] {
        for subscribed in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let connection = Uuid::new_v4();
            let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
            let raw = crate::redis::encode_array(&[b"message", b"jobs", b"opaque"]);
            let runtime = runtime(
                temp.path(),
                &[],
                &[
                    exchange(connection, 1, "SUBSCRIBE", &[b"jobs"], confirmation),
                    push(connection, None, &raw, 0),
                    push(connection, None, &raw, 0),
                    push(connection, None, &raw, 60000),
                ],
                lazy,
            )
            .await
            .unwrap();
            let task = if subscribed {
                let (mut client, task) = connect(&runtime).await;
                assert_eq!(
                    send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await,
                    confirmation
                );
                assert_eq!(read(&mut client).await, raw);
                assert_eq!(read(&mut client).await, raw);
                Some((client, task))
            } else {
                None
            };
            let report_path = temp.path().join("reports/report.json");
            let mut report = {
                let mut state = runtime.state.lock().await;
                state.finalized_at = Some(chrono::Utc::now());
                let report = state.snapshot_report();
                assert!(!report.is_dirty());
                serde_json::to_value(report).unwrap()
            };
            let details = crate::replay::report::global_evidence::prepare(
                runtime.state.clone(),
                &report_path,
            )
            .await
            .unwrap();
            report["global_evidence"] = details.manifests.clone();
            std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
            details.commit();
            let page =
                crate::replay::read_global_dependency_page(&report_path, "redis", 0, 100).unwrap();
            assert_eq!(page.total, if subscribed { 1 } else { 4 });
            assert_eq!(page.items.len(), page.total);
            assert_eq!(report["redis"]["pubsub"]["recorded_pushes"], 3);
            assert_eq!(
                report["redis"]["pubsub"]["delivered_pushes"],
                if subscribed { 2 } else { 0 }
            );
            assert_eq!(
                report["global_evidence"]["redis"]["notifications"]["remaining"],
                if subscribed { 1 } else { 3 }
            );
            if let Some((_, task)) = task {
                task.abort();
            }
        }
    }
}
