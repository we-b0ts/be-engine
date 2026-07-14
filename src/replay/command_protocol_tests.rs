use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::{MysqlReplayConfig, ReplayRuntime};

#[tokio::test]
async fn replays_redis_pipeline_in_recorded_lane_order() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let dependencies = [
        redis_dependency(connection_id, 1, "one", b"$1\r\n1\r\n"),
        redis_dependency(connection_id, 2, "two", b"$1\r\n2\r\n"),
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
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\none\r\n*2\r\n$3\r\nGET\r\n$3\r\ntwo\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 14];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n$1\r\n2\r\n");

    let report = wait_for_matched_count(&report_path, "redis", 2).await;
    assert_eq!(report["redis"]["matched"].as_array().unwrap().len(), 2);
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn replays_memcached_binary_with_live_opaque() {
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
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut request = vec![0_u8; 24];
    request[0] = 0x80;
    request[1] = 0x00;
    request[2..4].copy_from_slice(&3_u16.to_be_bytes());
    request[8..12].copy_from_slice(&3_u32.to_be_bytes());
    request[12..16].copy_from_slice(&42_u32.to_be_bytes());
    request.extend_from_slice(b"key");
    client.write_all(&request).await.unwrap();
    let mut response = vec![0_u8; 24];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(u32::from_be_bytes(response[12..16].try_into().unwrap()), 42);
    assert_eq!(u16::from_be_bytes(response[6..8].try_into().unwrap()), 0);

    let report = wait_for_matched_count(&report_path, "memcached", 1).await;
    assert_eq!(report["memcached"]["matched"].as_array().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn unsafe_redis_evidence_prevents_replay_startup() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"$1\r\n1\r\n");
    dependency["replay_safe"] = Value::Bool(false);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();

    let result = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case_dir.clone(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
            ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
            http_ignore_query_params: Vec::new(),
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("unsafe Redis evidence unexpectedly loaded"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unsafe"));
}

async fn spawn_replay(
    case_dir: &Path,
    report_path: Option<PathBuf>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case_dir.to_path_buf(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
            ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
            http_ignore_query_params: Vec::new(),
        },
        "127.0.0.1:0".parse().unwrap(),
        addr,
    )
    .await
    .unwrap();
    runtime.write_report().await.unwrap();
    let task = tokio::spawn(async move {
        let _ = runtime.run_tcp(listener).await;
    });
    (addr, task)
}

fn redis_dependency(connection_id: Uuid, sequence: u64, key: &str, response: &[u8]) -> Value {
    serde_json::json!({
        "event_type": "redis_exchange",
        "connection_id": connection_id,
        "sequence": sequence,
        "target_host": "redis.internal",
        "target_port": 6379,
        "resp_version": 2,
        "database": 0,
        "username": null,
        "command": "GET",
        "args": [capture_json(key.as_bytes())],
        "response_kind": "bulk_string",
        "response": capture_json(response),
        "session_setup": false,
        "replay_safe": true
    })
}

fn capture_json(bytes: &[u8]) -> Value {
    serde_json::json!({
        "encoding": "base64",
        "original_len": bytes.len(),
        "stored_len": bytes.len(),
        "data": STANDARD.encode(bytes),
        "truncated": false
    })
}

async fn wait_for_matched_count(path: &Path, protocol: &str, expected: usize) -> Value {
    for _ in 0..50 {
        if let Ok(raw) = tokio::fs::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report[protocol]["matched"]
                .as_array()
                .is_some_and(|matched| matched.len() == expected)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report did not reach {expected} {protocol} matches");
}
