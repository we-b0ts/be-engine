use super::*;

#[tokio::test]
async fn delivers_mysql_prefix_at_its_offset_then_server_eof() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-id");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let prefix = MysqlPacket {
        sequence_id: 1,
        payload: vec![0x01],
    }
    .to_wire_bytes();
    use base64::Engine;
    let dependency = serde_json::json!({
        "event_type":"mysql_exchange", "target_host":"mysql.internal", "target_port":3306,
        "database":"appdb", "username":"root", "command":"COM_QUERY", "sql":"SELECT incomplete_value",
        "response":{"status":"server_terminated", "wire_prefix":[{
            "offset_ms":30, "packet":{"encoding":"base64", "data":base64::engine::general_purpose::STANDARD.encode(&prefix)}
        }]},
        "outcome":{"terminated":{"side":"server", "kind":"eof", "scope":"write_half"}}, "duration_ms":80
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_vec(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let (addr, runtime, task) = spawn_replay(&case_dir).await;
    let mut client = connect_login(addr).await;
    let started = tokio::time::Instant::now();
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"SELECT incomplete_value".to_vec()].concat(),
        },
    )
    .await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(15),
            read_packet(&mut client)
        )
        .await
        .is_err()
    );
    let delivered = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        read_packet(&mut client),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(delivered.to_wire_bytes(), prefix);
    assert!(started.elapsed() >= std::time::Duration::from_millis(25));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            read_packet(&mut client)
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(75));
    for _ in 0..20 {
        if runtime.state.lock().await.mysql.events.matched_query_count == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let state = runtime.state.lock().await;
    assert_eq!(state.mysql.events.matched_query_count, 1);
    assert!(state.mysql.events.unsupported_commands.is_empty());
    drop(state);
    drop(client);
    task.abort();
}

#[tokio::test]
async fn replays_server_reset_instead_of_orderly_eof() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-id");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let dependency = serde_json::json!({
        "event_type":"mysql_exchange", "target_host":"mysql.internal", "target_port":3306,
        "database":"appdb", "username":"root", "command":"COM_QUERY", "sql":"SELECT reset_value",
        "response":{"status":"server_terminated"},
        "outcome":{"terminated":{"side":"server", "kind":"reset", "scope":"connection"}}, "duration_ms":40
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_vec(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let (addr, runtime, task) = spawn_replay(&case_dir).await;
    let mut client = connect_login(addr).await;
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"SELECT reset_value".to_vec()].concat(),
        },
    )
    .await;
    let error = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        read_packet(&mut client),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    for _ in 0..20 {
        if runtime.state.lock().await.mysql.events.matched_query_count == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        runtime.state.lock().await.mysql.events.matched_query_count,
        1
    );
    task.abort();
}

#[tokio::test]
async fn a_target_fin_before_server_deadline_is_dirty_and_unconsumed() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-id");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let dependency = serde_json::json!({
        "event_type":"mysql_exchange", "target_host":"mysql.internal", "target_port":3306,
        "database":"appdb", "username":"root", "command":"COM_QUERY", "sql":"SELECT early_end",
        "response":{"status":"server_terminated"},
        "outcome":{"terminated":{"side":"server", "kind":"eof", "scope":"write_half"}}, "duration_ms":200
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_vec(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let (addr, runtime, task) = spawn_replay(&case_dir).await;
    let mut client = connect_login(addr).await;
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"SELECT early_end".to_vec()].concat(),
        },
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    client.shutdown().await.unwrap();
    for _ in 0..40 {
        if !runtime
            .state
            .lock()
            .await
            .mysql
            .events
            .unmatched_queries
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let state = runtime.state.lock().await;
    assert_eq!(state.mysql.events.matched_query_count, 0);
    assert!(!state.mysql.events.unmatched_queries.is_empty());
    assert_eq!(state.unused_exchanges(ReplaySource::Case).len(), 1);
    drop(state);
    drop(client);
    task.abort();
}

#[tokio::test]
async fn ping_server_reset_is_not_replaced_by_builtin_ok() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-id");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let dependency = serde_json::json!({
        "event_type":"mysql_exchange", "target_host":"mysql.internal", "target_port":3306,
        "database":"appdb", "username":"root", "command":"COM_PING", "sql":null,
        "response":{"status":"server_terminated"},
        "outcome":{"terminated":{"side":"server", "kind":"reset", "scope":"connection"}}, "duration_ms":30
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_vec(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let (addr, runtime, task) = spawn_replay(&case_dir).await;
    let mut client = connect_login(addr).await;
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: vec![0x0e],
        },
    )
    .await;
    let error = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        read_packet(&mut client),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    for _ in 0..20 {
        if runtime.state.lock().await.mysql.events.matched_query_count == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let state = runtime.state.lock().await;
    assert_eq!(state.mysql.events.matched_query_count, 1);
    assert_eq!(state.mysql.events.builtin_query_count, 0);
    task.abort();
}
