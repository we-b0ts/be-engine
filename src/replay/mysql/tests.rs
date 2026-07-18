use super::*;

use std::path::{Path, PathBuf};

use tempfile::tempdir;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn active_case_exchanges_precede_identical_bootstrap_exchanges() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-id");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(
        temp.path().join("bootstrap-dependencies.jsonl"),
        format!(
            "{}\n{}\n",
            execute_dependency("bootstrap", false),
            builtin_dependency()
        ),
    )
    .await
    .unwrap();
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        format!(
            "{}\n{}\n",
            execute_dependency("case", true),
            builtin_dependency()
        ),
    )
    .await
    .unwrap();

    let (addr, runtime, task) = spawn_replay(&case_dir).await;
    let mut client = connect_login(addr).await;

    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x16], b"SELECT value FROM settings".to_vec()].concat(),
        },
    )
    .await;
    let prepare_ok = read_packet(&mut client).await.unwrap().unwrap();
    let statement_id = read_u32_le(&prepare_ok.payload, 1).unwrap();
    assert_eq!(read_u16_le(&prepare_ok.payload, 5), Some(1));
    let _column = read_packet(&mut client).await.unwrap().unwrap();
    let _column_eof = read_packet(&mut client).await.unwrap().unwrap();

    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: stmt_execute_no_params(statement_id),
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
    assert_eq!(
        row.payload,
        [vec![0x00, 0x00, 4], b"case".to_vec()].concat()
    );
    let _rows_eof = read_packet(&mut client).await.unwrap().unwrap();

    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"SET NAMES utf8".to_vec()].concat(),
        },
    )
    .await;
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0x00
    );

    let state = runtime.state.lock().await;
    assert_eq!(
        state.mysql.events.matched_queries[0].source,
        ReplaySource::Case
    );
    assert_eq!(
        state.mysql.events.builtin_queries[0].recorded_source,
        Some(ReplaySource::Case)
    );
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(state.unused_exchanges(ReplaySource::Bootstrap).len(), 2);
    drop(state);
    task.abort();
}

#[tokio::test]
async fn stmt_close_ignores_legacy_exchange_and_keeps_protocol_aligned() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-id");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        concat!(
            "{\"event_type\":\"mysql_connection\",\"id\":\"00000000-0000-0000-0000-000000000001\",",
            "\"target_host\":\"mysql.internal\",\"target_port\":3306,\"target_addr\":\"mysql.internal:3306\",",
            "\"database\":\"appdb\",\"username\":\"root\"}\n",
            "{\"event_type\":\"mysql_exchange\",\"target_host\":\"mysql.internal\",\"target_port\":3306,",
            "\"target_addr\":\"mysql.internal:3306\",\"database\":\"appdb\",\"username\":\"root\",",
            "\"command\":\"COM_UNKNOWN_0x19\",\"sql\":null,\"params\":null,",
            "\"response\":{\"status\":\"incomplete\",\"columns\":[],\"rows\":[]}}\n"
        ),
    )
    .await
    .unwrap();

    let (addr, runtime, task) = spawn_replay(&case_dir).await;
    let mut client = connect_login(addr).await;
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x19], 42_u32.to_le_bytes().to_vec()].concat(),
        },
    )
    .await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read_packet(&mut client)
        )
        .await
        .is_err()
    );

    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 0,
            payload: vec![0x0e],
        },
    )
    .await;
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0x00
    );

    let state = runtime.state.lock().await;
    assert!(state.mysql.events.unsupported_commands.is_empty());
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert!(!super::super::report_is_dirty(&state.snapshot_report()));
    drop(state);
    task.abort();
}

fn execute_dependency(value: &str, include_columns: bool) -> String {
    let columns = if include_columns {
        serde_json::json!([{
            "name": "value",
            "family": "string",
            "sql_type": "VARCHAR",
            "nullable": false
        }])
    } else {
        serde_json::json!([])
    };
    serde_json::json!({
        "event_type": "mysql_exchange",
        "target_host": "mysql.internal",
        "target_port": 3306,
        "target_addr": "mysql.internal:3306",
        "database": "appdb",
        "username": "root",
        "command": "COM_STMT_EXECUTE",
        "sql": "SELECT value FROM settings",
        "params": [],
        "response": {
            "status": "resultset",
            "columns": columns,
            "rows": [[{"kind": "string", "value": value}]]
        }
    })
    .to_string()
}

fn builtin_dependency() -> String {
    serde_json::json!({
        "event_type": "mysql_exchange",
        "target_host": "mysql.internal",
        "target_port": 3306,
        "target_addr": "mysql.internal:3306",
        "database": "appdb",
        "username": "root",
        "command": "COM_QUERY",
        "sql": "SET NAMES utf8",
        "response": {
            "status": "ok",
            "affected_rows": 0,
            "last_insert_id": 0
        }
    })
    .to_string()
}

async fn spawn_replay(
    case_dir: &Path,
) -> (SocketAddr, Arc<ReplayRuntime>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = Arc::new(
        ReplayRuntime::load(
            MysqlReplayConfig {
                case_dir: case_dir.to_path_buf(),
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(PathBuf::from(case_dir).join(".replay/ca.pem")),
                ca_key_path: Some(PathBuf::from(case_dir).join(".replay/ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: Vec::new(),
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
        )
        .await
        .unwrap(),
    );
    let task_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        task_runtime.run_tcp(listener).await.unwrap();
    });
    (addr, runtime, task)
}

async fn connect_login(addr: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _handshake = read_packet(&mut client).await.unwrap().unwrap();
    write_packet_bytes(
        &mut client,
        MysqlPacket {
            sequence_id: 1,
            payload: login_payload("appdb"),
        },
    )
    .await;
    assert_eq!(
        read_packet(&mut client).await.unwrap().unwrap().payload[0],
        0x00
    );
    client
}

async fn write_packet_bytes(stream: &mut TcpStream, packet: MysqlPacket) {
    stream.write_all(&packet.to_wire_bytes()).await.unwrap();
}

fn login_payload(database: &str) -> Vec<u8> {
    let flags =
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH;
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

fn stmt_execute_no_params(statement_id: u32) -> Vec<u8> {
    let mut payload = vec![0x17];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload
}
