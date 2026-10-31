//! Process-owned Redis replay behavior across source connection lanes.

use super::*;

#[tokio::test]
async fn finite_process_get_unblocks_recorded_case_in_a_loaded_replay() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let lane = Uuid::new_v4();
    let records = [
        redis_hash_dependency(lane, 1, "GET", &["monitor"], b"$1\r\n1\r\n"),
        redis_hash_dependency(lane, 2, "DEL", &["business"], b":1\r\n"),
        redis_hash_dependency(lane, 3, "GET", &["monitor"], b"$-1\r\n"),
    ];
    let original = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), &original)
        .await
        .unwrap();
    let rule = serde_json::from_value(serde_json::json!({
        "protocol":"redis","name":"monitor","ports":[6379],"command":"GET",
        "keys":["monitor"],"source_revision":"abcdef1","source_evidence":"monitor.py:loop"
    }))
    .unwrap();
    let case_dir =
        crate::replay::test_support::recording::centralize_partitioned(&case_dir, &[0, 2]).await;
    let frozen =
        crate::dependency_index::scoped::read_bytes(&case_dir.join("dependencies.jsonl")).unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) =
        spawn_replay_with_background(&case_dir, Some(report_path.clone()), vec![rule]).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    for (request, expected) in [
        (
            b"*2\r\n$3\r\nDEL\r\n$8\r\nbusiness\r\n".as_slice(),
            b":1\r\n".as_slice(),
        ),
        (
            b"*2\r\n$3\r\nGET\r\n$7\r\nmonitor\r\n".as_slice(),
            b"$1\r\n1\r\n".as_slice(),
        ),
        (
            b"*2\r\n$3\r\nGET\r\n$7\r\nmonitor\r\n".as_slice(),
            b"$-1\r\n".as_slice(),
        ),
    ] {
        client.write_all(request).await.unwrap();
        let mut response = vec![0; expected.len()];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, expected);
    }
    let report = wait_for_matched_count(&report_path, "redis", 3).await;
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    assert_eq!(
        crate::dependency_index::scoped::read_bytes(&case_dir.join("dependencies.jsonl")).unwrap(),
        frozen
    );
    task.abort();
}

#[tokio::test]
async fn background_hscan_does_not_block_a_following_mget_in_the_source_lane() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
        .await
        .unwrap();
    let connection_id = Uuid::new_v4();
    let mut hscan = redis_hash_dependency(
        connection_id,
        1,
        "HSCAN",
        &["dingtalk:card_inbox:257968", "0"],
        b"*2\r\n$1\r\n0\r\n*0\r\n",
    );
    hscan["global_dependency_reason"] = Value::String("background_rule".to_string());
    let mget = redis_hash_dependency(
        connection_id,
        2,
        "MGET",
        &["device:one", "device:two"],
        b"*2\r\n$1\r\n1\r\n$1\r\n2\r\n",
    );
    let global = [hscan, mget]
        .map(|value| serde_json::to_string(&value).unwrap())
        .join("\n");
    tokio::fs::write(case_dir.join("global-dependencies.jsonl"), global)
        .await
        .unwrap();
    let case_dir = crate::replay::test_support::recording::centralize(&case_dir, &[0]).await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*3\r\n$4\r\nMGET\r\n$10\r\ndevice:one\r\n$10\r\ndevice:two\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 18];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"*2\r\n$1\r\n1\r\n$1\r\n2\r\n");

    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}
