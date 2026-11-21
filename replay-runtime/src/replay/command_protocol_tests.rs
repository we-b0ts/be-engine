use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::{MysqlReplayConfig, ReplayRuntime};
use crate::BackgroundDependencyRuleConfig;

mod mysql_transaction;
mod redis_value_delivery;
mod unmatched_connection_tests;

async fn spawn_replay(
    case_dir: &Path,
    report_path: Option<PathBuf>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_configured(case_dir, report_path, None, Vec::new()).await
}

async fn spawn_replay_configured(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    policy_path: Option<PathBuf>,
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_with_providers(
        case_dir,
        report_path,
        policy_path,
        process_owned_dependencies,
        crate::protocols::default_providers(),
    )
    .await
}

async fn spawn_replay_with_providers(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    policy_path: Option<PathBuf>,
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
    providers: std::sync::Arc<crate::protocols::DependencyProviders>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    super::write_test_recording_network_manifest(case_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = ReplayRuntime::load_with_providers(
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
            policy_path,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies,
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        addr,
        super::ReplayLifecycleConfig::default(),
        providers,
    )
    .await
    .unwrap();
    runtime.write_report().await.unwrap();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = runtime.run_tcp(listener) => {},
            _ = runtime.run_report_writer() => {},
        }
    });
    (addr, task)
}

fn redis_dependency(connection_id: Uuid, sequence: u64, key: &str, response: &[u8]) -> Value {
    serde_json::json!({
        "event_type": "redis_exchange",
        "timestamp": "1970-01-01T00:16:40Z",
        "duration_ms": 0,
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
    for _ in 0..150 {
        if let Ok(raw) = traffic_engine_recording::recorder::test_io::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report["dependency_protocols"][protocol]["matched_count"].as_u64()
                == Some(expected as u64)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report did not reach {expected} {protocol} matches");
}

async fn wait_for_unmatched_count(path: &Path, protocol: &str, expected: usize) -> Value {
    for _ in 0..150 {
        if let Ok(raw) = traffic_engine_recording::recorder::test_io::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report["dependency_protocols"][protocol]["unmatched"]
                .as_array()
                .is_some_and(|unmatched| unmatched.len() == expected)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report did not reach {expected} {protocol} unmatched requests");
}

async fn request(client: &mut TcpStream, args: &[&str], expected: &[u8]) {
    let args = args.iter().map(|arg| arg.as_bytes()).collect::<Vec<_>>();
    client
        .write_all(&traffic_protocol_redis::encode_array(&args))
        .await
        .unwrap();
    let mut response = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, expected);
}

#[tokio::test]
async fn registered_value_policy_matches_redis_payload_without_protocol_specific_execution() {
    use std::sync::Arc;
    use traffic_contract::{
        codec::Codec,
        rule::{FieldContract, IdentityFormat},
    };
    use traffic_policy_value::{MessageSide, RuleBinding, ValueRule};
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    let mut source = redis_dependency(Uuid::new_v4(), 1, "key", b"+OK\r\n");
    source["command"] = "SET".into();
    source["args"] = serde_json::json!([
        capture_json(b"key"),
        capture_json(br#"{"id":42,"fixed":"original"}"#)
    ]);
    std::fs::write(case.join("dependencies.jsonl"), source.to_string()).unwrap();
    let mut providers = crate::protocols::default_providers().as_ref().clone();
    providers
        .bindings_mut()
        .register(
            "redis",
            MessageSide::Request,
            RuleBinding {
                rule: Arc::new(ValueRule {
                    id: "entity".into(),
                    contract: FieldContract::Identity {
                        prefix: String::new(),
                        format: IdentityFormat::Decimal,
                    },
                }),
                selector: serde_json::json!({"kind":"value"}),
                codec: Codec::Json,
                pointer: "/id".into(),
            },
            false,
        )
        .unwrap();
    let report = temp.path().join("report.json");
    let (address, task) = spawn_replay_with_providers(
        &case,
        Some(report.clone()),
        None,
        Vec::new(),
        Arc::new(providers),
    )
    .await;
    let mut client = TcpStream::connect(address).await.unwrap();
    request(
        &mut client,
        &["SET", "key", r#"{"id":99,"fixed":"original"}"#],
        b"+OK\r\n",
    )
    .await;
    let report = wait_for_matched_count(&report, "redis", 1).await;
    assert!(
        report["dependency_protocols"]["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}
