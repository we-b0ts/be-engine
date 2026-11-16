use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use super::{MysqlReplayConfig, ReplayRuntime};
use crate::{BackgroundDependencyRuleConfig, RedisKeyPatternConfig};

mod dynamic_values_tests;
mod redis_api_origin_tests;
mod redis_authentication_tests;
mod redis_client_info_tests;
mod redis_connection_tests;
mod redis_joint_time_tests;
mod redis_key_contract_tests;
mod redis_lane_tests;
mod redis_pipeline_tests;
mod redis_process_owned_tests;
mod redis_publish_tests;
mod redis_request_contract_tests;
mod redis_scalar_identity_tests;
mod redis_time_shift_tests;
mod redis_value_tests;
mod unmatched_connection_tests;

#[tokio::test]
async fn reports_redis_lane_blocker_without_exposing_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let connection_id = Uuid::new_v4();
    let dependencies = [
        redis_dependency(connection_id, 1, "private-key-one", b"$1\r\n1\r\n"),
        redis_dependency(connection_id, 2, "private-key-two", b"$1\r\n2\r\n"),
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
        .write_all(b"*2\r\n$3\r\nGET\r\n$15\r\nprivate-key-two\r\n")
        .await
        .unwrap();
    let mut response = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read(&mut response))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    let report = wait_for_unmatched_count(&report_path, "redis", 1).await;
    let diagnostic = &report["redis"]["unmatched"][0]["diagnostic"];
    assert_eq!(diagnostic["kind"], "lane_blocked");
    assert_eq!(diagnostic["candidate"]["sequence"], 2);
    assert_eq!(diagnostic["blocked_by"]["sequence"], 1);
    let serialized = serde_json::to_string(&report["redis"]["unmatched"][0]).unwrap();
    assert!(!serialized.contains("private-key-one"));
    assert!(!serialized.contains("private-key-two"));
    task.abort();
}

#[tokio::test]
async fn background_redis_gets_are_connection_independent() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
        .await
        .unwrap();
    let first_connection = Uuid::new_v4();
    let second_connection = Uuid::new_v4();
    let blocker = redis_dependency(first_connection, 1, "unrelated", b"$1\r\n0\r\n");
    let mut first = redis_dependency(first_connection, 2, "one", b"$1\r\n1\r\n");
    let mut second = redis_dependency(second_connection, 1, "two", b"$1\r\n2\r\n");
    for dependency in [&mut first, &mut second] {
        dependency["global_dependency_reason"] = Value::String("background_rule".to_string());
    }
    let global = [blocker, first, second]
        .map(|value| serde_json::to_string(&value).unwrap())
        .join("\n");
    tokio::fs::write(case_dir.join("global-dependencies.jsonl"), global)
        .await
        .unwrap();
    let case_dir = crate::replay::test_support::recording::centralize(&case_dir, &[1, 2]).await;
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
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn configured_bootstrap_hget_is_connection_independent() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), b"")
        .await
        .unwrap();
    let connection_id = Uuid::new_v4();
    let blocker = redis_hash_dependency(
        connection_id,
        1,
        "HGET",
        &["unrelated", "version"],
        b"$1\r\n0\r\n",
    );
    let mut selected = redis_hash_dependency(
        connection_id,
        2,
        "HGET",
        &["exp:matchlist:123", "version"],
        b"$1\r\n1\r\n",
    );
    selected["global_dependency_reason"] = Value::String("bootstrap_window".to_string());
    let global = [blocker, selected]
        .map(|value| serde_json::to_string(&value).unwrap())
        .join("\n");
    tokio::fs::write(case_dir.join("global-dependencies.jsonl"), global)
        .await
        .unwrap();
    let rule = BackgroundDependencyRuleConfig::Redis {
        key_sequence: Vec::new(),
        script: None,
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "experiment-bootstrap".to_string(),
        ports: vec![6379],
        command: "HGET".to_string(),
        keys: Vec::new(),
        key_patterns: vec![RedisKeyPatternConfig {
            prefix: "exp:matchlist:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: vec!["version".to_string()],
        source_revision: String::new(),
        source_evidence: "src/bootstrap.rs:load experiment cache".to_string(),
    };
    let case_dir = crate::replay::test_support::recording::centralize(&case_dir, &[]).await;
    let report_path = temp.path().join("report.json");
    let (addr, task) =
        spawn_replay_with_background(&case_dir, Some(report_path.clone()), vec![rule]).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*3\r\n$4\r\nHGET\r\n$17\r\nexp:matchlist:123\r\n$7\r\nversion\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n");
    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn delays_redis_response_by_recorded_duration() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"$1\r\n1\r\n");
    dependency["duration_ms"] = Value::from(80);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let (addr, task) = spawn_replay(&case_dir, None).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    let started = Instant::now();
    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
        .await
        .unwrap();
    let mut response = vec![0_u8; 7];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"$1\r\n1\r\n");
    assert!(started.elapsed() >= Duration::from_millis(70));
    task.abort();
}

#[tokio::test]
async fn consumes_redis_timeout_only_after_client_close() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let mut dependency = redis_dependency(Uuid::new_v4(), 1, "key", b"");
    dependency["response_kind"] = Value::String("other".to_string());
    dependency["outcome"] = Value::String("client_terminated".to_string());
    dependency["duration_ms"] = Value::from(60);
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        serde_json::to_string(&dependency).unwrap(),
    )
    .await
    .unwrap();
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, Some(report_path.clone())).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
        .await
        .unwrap();
    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut probe))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    client.shutdown().await.unwrap();

    let report = wait_for_matched_count(&report_path, "redis", 1).await;
    assert!(
        report["redis"]["unsafe_events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
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
    super::write_test_recording_network_manifest(&case_dir);

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
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
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
    spawn_replay_configured(case_dir, report_path, None, Vec::new()).await
}

async fn spawn_replay_with_background(
    case_dir: &Path,
    report_path: Option<PathBuf>,
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_replay_configured(case_dir, report_path, None, process_owned_dependencies).await
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
            policy_path,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies,
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        addr,
    )
    .await
    .unwrap();
    runtime.state.lock().await.providers = providers;
    runtime.write_report().await.unwrap();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = runtime.run_tcp(listener) => {},
            _ = runtime.run_report_writer() => {},
        }
    });
    (addr, task)
}

fn redis_hash_dependency(
    connection_id: Uuid,
    sequence: u64,
    command: &str,
    args: &[&str],
    response: &[u8],
) -> Value {
    let mut value = redis_dependency(
        connection_id,
        sequence,
        args.first().copied().unwrap_or_default(),
        response,
    );
    value["command"] = Value::String(command.to_string());
    value["args"] = Value::Array(
        args.iter()
            .map(|arg| {
                serde_json::json!({
                    "encoding": "utf8",
                    "data": arg,
                    "truncated": false,
                })
            })
            .collect(),
    );
    value
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
        if let Ok(raw) = crate::recorder::test_io::read_to_string(path).await
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

async fn wait_for_unmatched_count(path: &Path, protocol: &str, expected: usize) -> Value {
    for _ in 0..150 {
        if let Ok(raw) = crate::recorder::test_io::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report[protocol]["unmatched"]
                .as_array()
                .is_some_and(|unmatched| unmatched.len() == expected)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("replay report did not reach {expected} {protocol} unmatched requests");
}
