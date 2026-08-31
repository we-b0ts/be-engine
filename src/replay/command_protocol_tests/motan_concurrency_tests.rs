use super::*;

#[tokio::test]
async fn waits_for_concurrent_motan_predecessors_that_arrive_out_of_order() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let first_request = motan_request_for(1, "first");
    let second_request = motan_request_for(2, "second");
    let third_request = motan_request_for(3, "third");
    let first_response = motan_response(1, b"first-response");
    let second_response = motan_response(2, b"second-response");
    let third_response = motan_response(3, b"third-response");
    let dependencies = [
        motan_dependency_for(connection_id, 1, "first", &first_request, &first_response),
        motan_dependency_for(
            connection_id,
            2,
            "second",
            &second_request,
            &second_response,
        ),
        motan_dependency_for(connection_id, 3, "third", &third_request, &third_response),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client.write_all(&third_request).await.unwrap();
    let mut third_response_buffer = vec![0_u8; third_response.len()];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            client.read_exact(&mut third_response_buffer),
        )
        .await
        .is_err()
    );

    client.write_all(&first_request).await.unwrap();
    client.write_all(&second_request).await.unwrap();
    let mut first_response_buffer = vec![0_u8; first_response.len()];
    let mut second_response_buffer = vec![0_u8; second_response.len()];
    client.read_exact(&mut first_response_buffer).await.unwrap();
    client
        .read_exact(&mut second_response_buffer)
        .await
        .unwrap();
    client.read_exact(&mut third_response_buffer).await.unwrap();
    assert_eq!(first_response_buffer, first_response);
    assert_eq!(second_response_buffer, second_response);
    assert_eq!(third_response_buffer, third_response);

    let report = wait_for_matched_count(&report_path, "motan", 3).await;
    assert!(report["motan"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn reports_motan_lane_block_when_predecessor_never_arrives() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let first_request = motan_request_for(1, "first");
    let second_request = motan_request_for(2, "second");
    let dependencies = [
        motan_dependency_for(
            connection_id,
            1,
            "first",
            &first_request,
            &motan_response(1, b"first-response"),
        ),
        motan_dependency_for(
            connection_id,
            2,
            "second",
            &second_request,
            &motan_response(2, b"second-response"),
        ),
    ]
    .map(|value| serde_json::to_string(&value).unwrap())
    .join("\n");
    tokio::fs::write(case_dir.join("dependencies.jsonl"), dependencies)
        .await
        .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client.write_all(&second_request).await.unwrap();
    let mut response = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(250), client.read(&mut response))
        .await
        .expect("Motan lane wait did not terminate");
    assert_eq!(read.unwrap(), 0);

    let report = wait_for_unmatched_count(&report_path, "motan", 1).await;
    let diagnostic = &report["motan"]["unmatched"][0]["diagnostic"];
    assert_eq!(diagnostic["kind"], "lane_blocked");
    assert_eq!(diagnostic["candidate"]["sequence"], 2);
    assert_eq!(diagnostic["blocked_by"]["sequence"], 1);
    task.abort();
}

fn motan_request_for(request_id: u64, method: &str) -> Vec<u8> {
    let values = [
        "cn.sina.api.user.service.UserCounterService",
        method,
        "long",
    ];
    let mut block = Vec::new();
    for value in values {
        block.extend_from_slice(&(value.len() as u16).to_be_bytes());
        block.extend_from_slice(value.as_bytes());
    }
    let mut body = vec![0xAC, 0xED, 0x00, 0x05, 0x77, block.len() as u8];
    body.extend_from_slice(&block);
    motan_frame(request_id, true, 0, &body)
}

fn motan_dependency_for(
    connection_id: Uuid,
    sequence: u64,
    method: &str,
    request: &[u8],
    response: &[u8],
) -> Value {
    serde_json::json!({
        "event_type": "motan_exchange",
        "connection_id": connection_id,
        "sequence": sequence,
        "target_host": "vintage-node-10-145-1-107.trp.test",
        "target_port": 8881,
        "advertised_ip": "198.19.0.20",
        "codec_version": 1,
        "interface_name": "cn.sina.api.user.service.UserCounterService",
        "method_name": method,
        "parameter_desc": "long",
        "method_sign": null,
        "command": format!("cn.sina.api.user.service.UserCounterService#{method}"),
        "request": capture_json(request),
        "response": capture_json(response),
        "heartbeat": false,
        "outcome": "response",
        "duration_ms": 0,
        "replay_safe": true
    })
}
