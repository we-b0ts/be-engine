use super::*;

async fn assert_eof(client: &mut TcpStream) {
    let mut probe = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.read(&mut probe))
            .await
            .expect("unmatched dependency must close its connection")
            .unwrap(),
        0
    );
}

async fn fixture(
    records: &[Value],
) -> (
    tempfile::TempDir,
    PathBuf,
    SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(
        case.join("dependencies.jsonl"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let report = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case, Some(report.clone())).await;
    (temp, report, addr, task)
}

#[tokio::test]
async fn unmatched_redis_closes_connection_retains_blocker_and_accepts_fresh_connection() {
    let connection = Uuid::new_v4();
    let (_temp, path, addr, task) = fixture(&[
        redis_dependency(connection, 1, "first", b"$1\r\n1\r\n"),
        redis_dependency(connection, 2, "second", b"$1\r\n2\r\n"),
    ])
    .await;
    let mut rejected = TcpStream::connect(addr).await.unwrap();
    rejected
        .write_all(b"*2\r\n$3\r\nGET\r\n$6\r\nsecond\r\n")
        .await
        .unwrap();
    assert_eof(&mut rejected).await;
    let report = wait_for_unmatched_count(&path, "redis", 1).await;
    let event = &report["redis"]["unmatched"][0];
    assert_eq!(event["target_event_index"], 0);
    assert_eq!(event["diagnostic"]["kind"], "lane_blocked");
    assert_eq!(event["diagnostic"]["candidate"]["sequence"], 2);
    assert_eq!(event["diagnostic"]["blocked_by"]["sequence"], 1);
    assert_eq!(report["redis"]["unused_case"].as_array().unwrap().len(), 2);
    let mut fresh = TcpStream::connect(addr).await.unwrap();
    redis_value_tests::request(&mut fresh, &["GET", "first"], b"$1\r\n1\r\n").await;
    redis_value_tests::request(&mut fresh, &["GET", "second"], b"$1\r\n2\r\n").await;
    let report = wait_for_matched_count(&path, "redis", 2).await;
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 1);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn recorded_redis_error_keeps_connection_usable() {
    let connection = Uuid::new_v4();
    let mut error = redis_dependency(connection, 1, "first", b"-ERR source rejected\r\n");
    error["response_kind"] = "error".into();
    let (_temp, path, addr, task) = fixture(&[
        error,
        redis_dependency(connection, 2, "second", b"$1\r\n2\r\n"),
    ])
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    redis_value_tests::request(&mut client, &["GET", "first"], b"-ERR source rejected\r\n").await;
    redis_value_tests::request(&mut client, &["GET", "second"], b"$1\r\n2\r\n").await;
    let report = wait_for_matched_count(&path, "redis", 2).await;
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}
