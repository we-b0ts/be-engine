//! Generic Replay entrypoint fixtures for finite HTTP assembly tests.
use crate::replay::{MysqlReplayConfig, ReplayAllowedUnusedHttpConfig, ReplayRuntime};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
#[allow(dead_code)]
pub async fn spawn_http_replay(
    case_dir: &Path,
    ignored_query_params: Vec<String>,
) -> (
    std::net::SocketAddr,
    Arc<ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    spawn_http_replay_with_policy(case_dir, ignored_query_params, None, None).await
}

pub async fn spawn_http_replay_with_policy(
    case_dir: &Path,
    ignored_query_params: Vec<String>,
    policy_path: Option<PathBuf>,
    allowed_unused_http: Option<ReplayAllowedUnusedHttpConfig>,
) -> (
    std::net::SocketAddr,
    Arc<ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    crate::replay::write_test_recording_network_manifest(case_dir);
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
                report_path: Some(case_dir.join(".replay/report.json")),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
                ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
                policy_path,
                http_ignore_query_params: ignored_query_params,
                process_owned_dependencies: Vec::new(),
                allowed_unused_http,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
        )
        .await
        .unwrap(),
    );
    let task_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = task_runtime.run_tcp(listener) => {},
            _ = task_runtime.run_report_writer() => {},
        }
    });
    (addr, runtime, task)
}

pub async fn write_http_case(
    case_dir: &Path,
    scheme: &str,
    authority: &str,
    uri: &str,
    request_body: &str,
    response_body: &str,
) {
    tokio::fs::create_dir_all(case_dir).await.unwrap();
    write_http_dependency(
        &case_dir.join("dependencies.jsonl"),
        scheme,
        authority,
        uri,
        request_body,
        response_body,
    )
    .await;
}

pub async fn write_http_dependency(
    path: &Path,
    scheme: &str,
    authority: &str,
    uri: &str,
    request_body: &str,
    response_body: &str,
) {
    let dependency = serde_json::json!({
        "event_type": "http_exchange",
        "request_started_at": "2026-07-15T04:30:00Z",
        "timestamp": "2026-07-15T04:30:00Z",
        "duration_ms": 0,
        "scheme": scheme,
        "id": uuid::Uuid::new_v4(),
        "method": "POST", "request_headers":{"host":[authority]},
        "uri": uri,
        "authority": authority,
        "request_body": body_capture(request_body),
        "response_status": 200,
        "response_headers": {"content-type": ["text/plain"], "content-length": [response_body.len().to_string()]},
        "response_body": body_capture(response_body),
        "error": null
    });
    tokio::fs::write(
        path,
        format!("{}\n", serde_json::to_string(&dependency).unwrap()),
    )
    .await
    .unwrap();
}

fn body_capture(value: &str) -> Value {
    serde_json::json!({
        "encoding": "base64",
        "original_len": value.len(),
        "stored_len": value.len(),
        "truncated": false,
        "data": STANDARD.encode(value.as_bytes())
    })
}

/// Opaque test adapter keeps Replay's internal runtime inside its owner.
pub struct TestHttpReplayRuntime(Arc<ReplayRuntime>);

pub async fn spawn_coordinator_http_replay(
    case: &Path,
    policy: Option<PathBuf>,
) -> (
    std::net::SocketAddr,
    TestHttpReplayRuntime,
    tokio::task::JoinHandle<()>,
) {
    let (addr, runtime, task) = spawn_http_replay_with_policy(case, vec![], policy, None).await;
    (addr, TestHttpReplayRuntime(runtime), task)
}

pub async fn snapshot_http_replay(runtime: &TestHttpReplayRuntime) -> Value {
    serde_json::to_value(runtime.0.state.lock().await.snapshot_report()).unwrap()
}
