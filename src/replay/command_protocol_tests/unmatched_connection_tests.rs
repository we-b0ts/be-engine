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

#[tokio::test]
async fn unmatched_memcached_binary_closes_connection_and_accepts_fresh_connection() {
    let (_temp, path, addr, task) =
        fixture(&[memcached_binary_dependency(Uuid::new_v4(), 1, b"key")]).await;
    let mut rejected = TcpStream::connect(addr).await.unwrap();
    rejected
        .write_all(&binary_get_request_for(42, b"wrong"))
        .await
        .unwrap();
    assert_eof(&mut rejected).await;
    let report = wait_for_unmatched_count(&path, "memcached", 1).await;
    assert_eq!(report["memcached"]["unmatched"][0]["target_event_index"], 0);
    assert!(report["memcached"]["unmatched"][0]["diagnostic"].is_object());
    assert_eq!(
        report["memcached"]["unused_case"].as_array().unwrap().len(),
        1
    );
    let mut fresh = TcpStream::connect(addr).await.unwrap();
    fresh.write_all(&binary_get_request(43)).await.unwrap();
    let mut header = [0; 24];
    fresh.read_exact(&mut header).await.unwrap();
    assert_eq!(&header[6..8], &0_u16.to_be_bytes());
    let report = wait_for_matched_count(&path, "memcached", 1).await;
    assert!(
        report["memcached"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn unmatched_memcached_text_and_noreply_close_connection() {
    for request in [
        b"get wrong\r\n".as_slice(),
        b"set wrong 0 0 1 noreply\r\nx\r\n".as_slice(),
    ] {
        let record = serde_json::json!({
            "event_type":"memcached_exchange", "connection_id":Uuid::new_v4(), "sequence":1,
            "target_host":"cache.internal", "target_port":11211, "wire_protocol":"text",
            "command":"get", "key":capture_json(b"key"), "args":[], "quiet":false,
            "noreply":false, "no_response":false, "response_frames":[capture_json(b"END\r\n")], "replay_safe":true
        });
        let (_temp, path, addr, task) = fixture(&[record]).await;
        let mut rejected = TcpStream::connect(addr).await.unwrap();
        rejected.write_all(request).await.unwrap();
        assert_eof(&mut rejected).await;
        let report = wait_for_unmatched_count(&path, "memcached", 1).await;
        assert_eq!(
            report["memcached"]["unused_case"].as_array().unwrap().len(),
            1
        );
        let mut fresh = TcpStream::connect(addr).await.unwrap();
        fresh.write_all(b"get key\r\n").await.unwrap();
        let mut response = [0; 5];
        fresh.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"END\r\n");
        wait_for_matched_count(&path, "memcached", 1).await;
        task.abort();
    }
}

#[tokio::test]
async fn recorded_memcached_error_keeps_connection_usable() {
    let connection = Uuid::new_v4();
    let record = |sequence, key: &[u8], response: &[u8]| {
        serde_json::json!({
            "event_type":"memcached_exchange", "connection_id":connection, "sequence":sequence,
            "target_host":"cache.internal", "target_port":11211, "wire_protocol":"text",
            "command":"get", "key":capture_json(key), "args":[], "quiet":false,
            "noreply":false, "no_response":false, "response_frames":[capture_json(response)], "replay_safe":true
        })
    };
    let error = b"SERVER_ERROR recorded source failure\r\n";
    let (_temp, path, addr, task) =
        fixture(&[record(1, b"first", error), record(2, b"second", b"END\r\n")]).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"get first\r\n").await.unwrap();
    let mut response = vec![0; error.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, error);
    client.write_all(b"get second\r\n").await.unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"END\r\n");
    let report = wait_for_matched_count(&path, "memcached", 2).await;
    assert!(
        report["memcached"]["unmatched"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}
