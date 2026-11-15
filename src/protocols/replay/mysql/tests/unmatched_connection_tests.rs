use super::*;

fn record(sql: &str, response: serde_json::Value) -> String {
    serde_json::json!({
        "event_type":"mysql_exchange", "target_host":"mysql.internal", "target_port":3306,
        "database":"appdb", "username":"root", "command":"COM_QUERY", "sql":sql,
        "response":response
    })
    .to_string()
}

async fn command(client: &mut TcpStream, payload: Vec<u8>) -> MysqlPacket {
    write_packet_bytes(
        client,
        MysqlPacket {
            sequence_id: 0,
            payload,
        },
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(2), read_packet(client))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

async fn assert_eof(client: &mut TcpStream) {
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), read_packet(client))
            .await
            .expect("unmatched MySQL request must close its connection")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unmatched_mysql_query_and_execute_close_connections_without_consuming_source() {
    for prepared in [false, true] {
        let temp = tempdir().unwrap();
        let case = temp.path().join("case-id");
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(
            case.join("dependencies.jsonl"),
            record("SELECT recorded_value", serde_json::json!({"status":"ok"})),
        )
        .unwrap();
        let (addr, runtime, task) = spawn_replay(&case).await;
        let mut rejected = connect_login(addr).await;
        let payload = if prepared {
            let prepare = command(
                &mut rejected,
                [vec![0x16], b"SELECT wrong_value".to_vec()].concat(),
            )
            .await;
            assert_eq!(prepare.payload[0], 0);
            stmt_execute_no_params(read_u32_le(&prepare.payload, 1).unwrap())
        } else {
            [vec![0x03], b"SELECT wrong_value".to_vec()].concat()
        };
        write_packet_bytes(
            &mut rejected,
            MysqlPacket {
                sequence_id: 0,
                payload,
            },
        )
        .await;
        assert_eof(&mut rejected).await;
        {
            let state = runtime.state.lock().await;
            assert_eq!(state.protocols.mysql.events.unmatched_queries.len(), 1);
            let event = &state.protocols.mysql.events.unmatched_queries[0];
            assert_eq!(
                event.command,
                if prepared {
                    "COM_STMT_EXECUTE"
                } else {
                    "COM_QUERY"
                }
            );
            assert_eq!(event.sql.as_deref(), Some("SELECT wrong_value"));
            assert!(event.target_event_index.is_some());
            assert!(event.reason.contains("no recorded semantic dependency"));
            assert_eq!(state.unused_exchanges(ReplaySource::Case).len(), 1);
        }
        let mut fresh = connect_login(addr).await;
        let response = command(
            &mut fresh,
            [vec![0x03], b"SELECT recorded_value".to_vec()].concat(),
        )
        .await;
        assert_eq!(response.payload[0], 0);
        assert!(
            runtime
                .state
                .lock()
                .await
                .unused_exchanges(ReplaySource::Case)
                .is_empty()
        );
        task.abort();
    }
}

#[tokio::test]
async fn unknown_mysql_statement_closes_connection() {
    let temp = tempdir().unwrap();
    let case = temp.path().join("case-id");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(
        case.join("dependencies.jsonl"),
        record("SELECT recorded_value", serde_json::json!({"status":"ok"})),
    )
    .unwrap();
    let (addr, runtime, task) = spawn_replay(&case).await;
    let mut rejected = connect_login(addr).await;
    write_packet_bytes(
        &mut rejected,
        MysqlPacket {
            sequence_id: 0,
            payload: stmt_execute_no_params(99),
        },
    )
    .await;
    assert_eof(&mut rejected).await;
    let mut fresh = connect_login(addr).await;
    assert_eq!(
        command(
            &mut fresh,
            [vec![0x03], b"SELECT recorded_value".to_vec()].concat()
        )
        .await
        .payload[0],
        0
    );
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .mysql
            .events
            .unmatched_queries
            .len(),
        1
    );
    task.abort();
}

#[tokio::test]
async fn recorded_mysql_1105_error_keeps_connection_usable() {
    let temp = tempdir().unwrap();
    let case = temp.path().join("case-id");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(case.join("dependencies.jsonl"), [
        record("SELECT source_error", serde_json::json!({"status":"error", "error_code":1105, "error_message":"recorded source error"})),
        record("SELECT recorded_value", serde_json::json!({"status":"ok"})),
    ].join("\n")).unwrap();
    let (addr, runtime, task) = spawn_replay(&case).await;
    let mut client = connect_login(addr).await;
    let error = command(
        &mut client,
        [vec![0x03], b"SELECT source_error".to_vec()].concat(),
    )
    .await;
    assert_eq!(read_u16_le(&error.payload, 1), Some(1105));
    assert_eq!(
        command(
            &mut client,
            [vec![0x03], b"SELECT recorded_value".to_vec()].concat()
        )
        .await
        .payload[0],
        0
    );
    let state = runtime.state.lock().await;
    assert!(state.protocols.mysql.events.unmatched_queries.is_empty());
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    task.abort();
}
