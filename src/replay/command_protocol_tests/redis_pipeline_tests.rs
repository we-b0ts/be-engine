use super::*;

#[tokio::test]
async fn replays_redis_pipeline_in_recorded_lane_order() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let dependencies = [
        redis_dependency(connection_id, 1, "one", b"$1\r\n1\r\n"),
        redis_dependency(connection_id, 2, "two", b"$1\r\n2\r\n"),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (providers, counts) = crate::protocols::tests::counted_providers();
    let (addr, task) = spawn_replay_with_providers(
        &case_dir,
        Some(report_path.clone()),
        None,
        Vec::new(),
        providers,
    )
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\none\r\n*2\r\n$3\r\nGET\r\n$3\r\ntwo\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 14];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n$1\r\n2\r\n");

    let report = wait_for_matched_count(&report_path, "redis", 2).await;
    assert_eq!(report["redis"]["matched"].as_array().unwrap().len(), 2);
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    assert_eq!(
        counts
            .redis
            .sessions
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        counts
            .redis
            .native_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    task.abort();
}
