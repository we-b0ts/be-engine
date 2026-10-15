use super::*;

#[tokio::test]
async fn replays_memcached_binary_with_live_opaque() {
    for global in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        let mut recorded_response = vec![0_u8; 24];
        recorded_response[0] = 0x81;
        recorded_response[1] = 0x00;
        recorded_response[12..16].copy_from_slice(&1_u32.to_be_bytes());
        let dependency = serde_json::json!({
            "event_type": "memcached_exchange",
            "connection_id": Uuid::new_v4(),
            "sequence": 1,
            "target_host": "cache.internal",
            "target_port": 11211,
            "wire_protocol": "binary",
            "command": "get",
            "opcode": 0,
            "key": capture_json(b"key"),
            "args": [],
            "value": null,
            "extras": null,
            "cas": null,
            "quiet": false,
            "noreply": false,
            "response_status": "0",
            "response_frames": [capture_json(&recorded_response)],
            "no_response": false,
            "replay_safe": true
        });
        tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
            .await
            .unwrap();
        tokio::fs::write(
            if global {
                temp.path().join("global-dependencies.jsonl")
            } else {
                case_dir.join("dependencies.jsonl")
            },
            serde_json::to_string(&dependency).unwrap(),
        )
        .await
        .unwrap();
        let report_path = temp.path().join("report.json");
        let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let request = binary_get_request(42);
        client.write_all(&request).await.unwrap();
        let mut response = vec![0_u8; 24];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(u32::from_be_bytes(response[12..16].try_into().unwrap()), 42);
        assert_eq!(u16::from_be_bytes(response[6..8].try_into().unwrap()), 0);

        let report = wait_for_matched_count(&report_path, "memcached", 1).await;
        assert_eq!(report["memcached"]["matched"].as_array().unwrap().len(), 1);
        client.write_all(&binary_get_request(43)).await.unwrap();
        client.read_exact(&mut response).await.unwrap();
        assert_ne!(
            u16::from_be_bytes(response[6..8].try_into().unwrap()),
            0,
            "finite response evidence must not be reused"
        );
        task.abort();
    }
}

#[tokio::test]
async fn one_memcached_target_connection_consumes_multiple_recorded_source_lanes() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let read_connection = Uuid::new_v4();
    let write_connection = Uuid::new_v4();
    let dependencies = [
        memcached_binary_dependency(read_connection, 1, b"u42"),
        memcached_binary_set_dependency(write_connection, 1, b"u42", b"value"),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(&binary_get_request_for(41, b"u42"))
        .await
        .unwrap();
    let mut get_response = vec![0_u8; 24];
    client.read_exact(&mut get_response).await.unwrap();
    assert_eq!(
        u32::from_be_bytes(get_response[12..16].try_into().unwrap()),
        41
    );
    assert_eq!(
        u16::from_be_bytes(get_response[6..8].try_into().unwrap()),
        0
    );

    client
        .write_all(&binary_set_request(42, b"u42", b"value"))
        .await
        .unwrap();
    let mut set_response = vec![0_u8; 24];
    client.read_exact(&mut set_response).await.unwrap();
    assert_eq!(
        u32::from_be_bytes(set_response[12..16].try_into().unwrap()),
        42
    );
    assert_eq!(
        u16::from_be_bytes(set_response[6..8].try_into().unwrap()),
        0
    );

    let report = wait_for_matched_count(&report_path, "memcached", 2).await;
    let matched = report["memcached"]["matched"].as_array().unwrap();
    assert_eq!(matched.len(), 2);
    assert_eq!(matched[0]["connection_id"], read_connection.to_string());
    assert_eq!(matched[1]["connection_id"], write_connection.to_string());
    assert!(
        report["memcached"]["unmatched"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn cross_lane_memcached_matching_preserves_each_source_lane_order() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let dependencies = [
        memcached_binary_dependency(connection_id, 1, b"first"),
        memcached_binary_dependency(connection_id, 2, b"second"),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(&binary_get_request_for(42, b"second"))
        .await
        .unwrap();
    let mut response = vec![0_u8; 24];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(
        u16::from_be_bytes(response[6..8].try_into().unwrap()),
        0x0084
    );

    let report = wait_for_unmatched_count(&report_path, "memcached", 1).await;
    let diagnostic = &report["memcached"]["unmatched"][0]["diagnostic"];
    assert_eq!(diagnostic["kind"], "lane_blocked");
    assert_eq!(diagnostic["candidate"]["sequence"], 2);
    assert_eq!(diagnostic["blocked_by"]["sequence"], 1);
    task.abort();
}

fn memcached_binary_set_dependency(
    connection_id: Uuid,
    sequence: u64,
    key: &[u8],
    value: &[u8],
) -> Value {
    let mut response = vec![0_u8; 24];
    response[0] = 0x81;
    response[1] = 0x01;
    serde_json::json!({
        "event_type": "memcached_exchange",
        "connection_id": connection_id,
        "sequence": sequence,
        "target_host": "cache.internal",
        "target_port": 11211,
        "wire_protocol": "binary",
        "command": "set",
        "opcode": 1,
        "key": capture_json(key),
        "args": [],
        "value": capture_json(value),
        "extras": capture_json(&[0_u8; 8]),
        "cas": null,
        "quiet": false,
        "noreply": false,
        "response_status": "0",
        "response_frames": [capture_json(&response)],
        "no_response": false,
        "replay_safe": true
    })
}
