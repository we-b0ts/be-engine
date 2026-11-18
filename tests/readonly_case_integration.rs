use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_e2e::{AppConfig, HttpGatewayRuleConfig, RecordingAccessPolicy};

#[tokio::test]
async fn rejected_http_dependency_invalidates_active_gateway_case() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let reserved_ports = ReservedPorts::<2>::new();
    let [proxy_addr, gateway_addr] = reserved_ports.addresses();
    let dependency = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dependency_addr = dependency.local_addr().unwrap();
    let dependency_task = tokio::spawn(async move {
        let (mut stream, _) = dependency.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        assert!(request.starts_with("GET "));
        assert!(request.contains("/dependency/read"));
        write_http_response(&mut stream, r#"{"ok":true}"#).await;

        assert!(
            tokio::time::timeout(Duration::from_millis(500), dependency.accept())
                .await
                .is_err(),
            "blocked dependency POST reached the upstream"
        );
    });

    let matched = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let matched_addr = matched.local_addr().unwrap();
    let matched_task = tokio::spawn(async move {
        let (mut stream, _) = matched.accept().await.unwrap();
        let gateway_request = read_http_request(&mut stream).await;
        assert!(gateway_request.starts_with("GET /scenario/readonly "));

        let dependency_get = send_http_request(
            proxy_addr,
            format!(
                "GET http://{dependency_addr}/dependency/read HTTP/1.1\r\nHost: {dependency_addr}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(dependency_get.contains("200 OK"));

        let dependency_post = send_http_request(
            proxy_addr,
            format!(
                "POST http://{dependency_addr}/dependency/write HTTP/1.1\r\nHost: {dependency_addr}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
        .await;
        assert!(dependency_post.contains("403 Forbidden"));

        write_http_response(&mut stream, r#"{"ok":true}"#).await;
    });

    let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = AppConfig::default();
    config.http.enabled = true;
    config.http.listen = proxy_addr;
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_addr}");
    config.http_gateway.fallback_upstream = format!("http://{}", fallback.local_addr().unwrap());
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("readonly".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/scenario/readonly".to_string()],
        ..Default::default()
    }];
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_e2e::AppState::new(config).await.unwrap();
    let recorder = state.recorder().clone();
    drop(reserved_ports);
    let recorder_task = tokio::spawn(async move { state.run().await });
    wait_for_port(proxy_addr).await;
    wait_for_port(gateway_addr).await;

    let response = send_http_request(
        gateway_addr,
        "GET /scenario/readonly HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            .to_string(),
    )
    .await;
    assert!(response.contains("200 OK"));
    matched_task.await.unwrap();
    dependency_task.await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    recorder_task.abort();
    recorder.flush_traffic().await.unwrap();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    assert!(!run_dir.join("readonly").exists());
    let failed_group = run_dir.join("failed/scenario-readonly");
    let failed_cases = std::fs::read_dir(&failed_group)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(failed_cases.len(), 1);
    let failed_case = &failed_cases[0];
    assert!(failed_case.join("request.json.invalid").exists());
    assert!(failed_case.join("expected-response.json.invalid").exists());
    assert!(!failed_case.join("request.json").exists());

    let dependencies = read_json_lines(&failed_case.join("dependencies.jsonl"));
    assert!(dependencies.iter().any(|event| {
        event["event_type"] == "http_exchange"
            && event["method"] == "GET"
            && event["uri"]
                .as_str()
                .is_some_and(|uri| uri.contains("/dependency/read"))
    }));
    assert!(dependencies.iter().any(|event| {
        event["event_type"] == "readonly_rejection"
            && event["operation_class"] == "write"
            && event["operation"] == "POST"
            && event["target"]
                .as_str()
                .is_some_and(|target| target.contains("/dependency/write"))
    }));
    assert!(
        !dependencies
            .iter()
            .any(|event| { event["event_type"] == "http_exchange" && event["method"] == "POST" })
    );

    let error: Value = serde_json::from_str(
        &std::fs::read_to_string(failed_case.join("recording-error.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(error["reason"], "recording_access_policy_rejection");
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("recording-run.json")).unwrap())
            .unwrap();
    assert_eq!(report["status"], "running");
    assert_eq!(report["published_cases"], 0);
    assert_eq!(report["failed_cases"], 1);
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&request).to_string()
}

async fn write_http_response(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

async fn send_http_request(addr: SocketAddr, request: String) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).to_string()
}

struct ReservedPorts<const N: usize> {
    listeners: [StdTcpListener; N],
}

impl<const N: usize> ReservedPorts<N> {
    fn new() -> Self {
        Self {
            listeners: std::array::from_fn(|_| StdTcpListener::bind("127.0.0.1:0").unwrap()),
        }
    }

    fn addresses(&self) -> [SocketAddr; N] {
        std::array::from_fn(|index| self.listeners[index].local_addr().unwrap())
    }
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("port {addr} did not open");
}

fn only_recording_run_dir(recordings_dir: &Path) -> PathBuf {
    let run_dirs = std::fs::read_dir(recordings_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(run_dirs.len(), 1);
    run_dirs[0].clone()
}

fn read_json_lines(path: &Path) -> Vec<Value> {
    if path
        .file_name()
        .is_some_and(|name| name == "dependencies.jsonl")
        && !path.is_file()
    {
        use std::io::{Read, Seek, SeekFrom};
        let scope_path = path.with_file_name("dependency-scope.json");
        let scope: Value = serde_json::from_slice(&std::fs::read(&scope_path).unwrap()).unwrap();
        let ledger = scope_path
            .parent()
            .unwrap()
            .join(scope["run_relpath"].as_str().unwrap())
            .join("dependencies.jsonl");
        let mut input = std::fs::File::open(ledger).unwrap();
        return scope["locations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|location| {
                input
                    .seek(SeekFrom::Start(location["offset"].as_u64().unwrap()))
                    .unwrap();
                let mut bytes = vec![0; location["length"].as_u64().unwrap() as usize];
                input.read_exact(&mut bytes).unwrap();
                serde_json::from_slice(&bytes).unwrap()
            })
            .collect();
    }
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
