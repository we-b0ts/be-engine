//! Sequential requests through two ordinary pooled RESP sockets.
use super::*;
use redis_value_tests::{request, spawn};

#[tokio::test]
async fn redis_get_del_on_pooled_connections_keeps_lane_order_across_response_delivery() {
    let temp = crate::policy::runtime::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    let lane = Uuid::new_v4();
    let mut records = Vec::new();
    for i in 0..100_u64 {
        let key = format!("session:{i}");
        records.push(redis_dependency(lane, 2 * i + 1, &key, b"$1\r\nx\r\n"));
        let mut del = redis_hash_dependency(lane, 2 * i + 2, "DEL", &[&key], b":1\r\n");
        del["response_kind"] = "integer".into();
        records.push(del);
    }
    std::fs::write(
        case.join("dependencies.jsonl"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let (addr, state, task) = spawn(&case, None).await;
    let mut reader = TcpStream::connect(addr).await.unwrap();
    let mut deleter = TcpStream::connect(addr).await.unwrap();
    request(&mut deleter, &["DEL", "session:0"], b"").await;
    deleter = TcpStream::connect(addr).await.unwrap();
    for i in 0..100 {
        let key = format!("session:{i}");
        request(&mut reader, &["GET", &key], b"$1\r\nx\r\n").await;
        request(&mut deleter, &["DEL", &key], b":1\r\n").await;
    }
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 200);
    assert_eq!(report["redis"]["unmatched"].as_array().unwrap().len(), 1);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}
