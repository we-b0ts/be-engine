async fn write_string_dependency(case_dir: &Path, sql: &str, value: &str) {
    tokio::fs::create_dir_all(case_dir).await.unwrap();
    let dependency = serde_json::json!({
        "event_type": "mysql_exchange",
        "target_host": "mysql.internal",
        "target_port": 3306,
        "target_addr": "mysql.internal:3306",
        "database": "appdb",
        "username": "root",
        "command": "COM_QUERY",
        "sql": sql,
        "response": {
            "status": "resultset",
            "columns": [{
                "name": "name",
                "table": "user",
                "column": "name",
                "family": "string",
                "sql_type": "VARCHAR",
                "nullable": false
            }],
            "rows": [[{"kind": "string", "value": value}]]
        }
    });
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
}

async fn query_one_string(addr: SocketAddr, sql: &str, expected: &str) {
    let mut client = connect_login(addr).await;
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], sql.as_bytes().to_vec()].concat(),
        },
    )
    .await;
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload,
        vec![1]
    );
    let _column = read_packet(&mut client).await.unwrap().unwrap();
    let _columns_eof = read_packet(&mut client).await.unwrap().unwrap();
    let row = read_packet(&mut client).await.unwrap().unwrap();
    assert_eq!(row.payload, lenenc_bytes(expected.as_bytes()));
    let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();
}

fn abort_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks {
        task.abort();
    }
}

async fn connect_login(addr: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let handshake = read_packet(&mut client).await.unwrap().unwrap();
    assert_eq!(handshake.sequence_id, 0);
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 1,
            payload: login_payload("appdb"),
        },
    )
    .await;
    let ok = read_packet(&mut client).await.unwrap().unwrap();
    assert_eq!(ok.payload[0], 0x00);
    client
}

async fn write_packet_bytes(stream: &mut TcpStream, packet: MysqlPacket) {
    stream.write_all(&packet.to_wire_bytes()).await.unwrap();
}

fn nul_terminated_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .expect("missing NUL terminator")
}

fn replay_column_type_and_flags(payload: &[u8]) -> (u8, u16) {
    let mut offset = 0;
    for _ in 0..6 {
        let (_, next) = read_lenenc_bytes(payload, offset).expect("lenenc column field");
        offset = next;
    }
    let (_, offset) = read_lenenc_int(payload, offset).expect("column fixed length marker");
    let type_code = *payload.get(offset + 6).expect("column type code");
    let flags = u16::from_le_bytes([
        *payload.get(offset + 7).expect("column flags low byte"),
        *payload.get(offset + 8).expect("column flags high byte"),
    ]);
    (type_code, flags)
}

fn login_payload(database: &str) -> Vec<u8> {
    let flags = CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PLUGIN_AUTH;
    let mut payload = Vec::new();
    payload.extend_from_slice(&flags.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&[0; 23]);
    payload.extend_from_slice(b"root\0");
    payload.push(0);
    payload.extend_from_slice(database.as_bytes());
    payload.push(0);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}

fn stmt_execute_long_param(statement_id: u32, value: u32) -> Vec<u8> {
    let mut payload = vec![0x17];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.push(0);
    payload.push(1);
    payload.push(MYSQL_TYPE_LONG);
    payload.push(0);
    payload.extend_from_slice(&value.to_le_bytes());
    payload
}

fn dns_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x1234_u16.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet
}

async fn wait_for_report_contains(path: &Path, expected: &str) {
    for _ in 0..50 {
        if tokio::fs::read_to_string(path)
            .await
            .is_ok_and(|raw| raw.contains(expected))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report was not written");
}
