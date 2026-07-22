use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hyper::StatusCode;
use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_e2e::{AppConfig, CompareConfig, HttpGatewayReadyConfig, HttpGatewayRuleConfig};

#[tokio::test]
async fn returns_baseline_without_waiting_for_candidate_and_records_both() {
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("baseline", 1).await;
    let candidate = spawn_delayed_upstream("candidate", 1, Duration::from_millis(300)).await;
    let gateway = free_addr();
    let run_id = "20260722160000";
    let config = compare_config(&temp, gateway, baseline, candidate);
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    let started = Instant::now();
    assert!(raw_get(gateway, "/api/users").await.contains("baseline"));
    assert!(started.elapsed() < Duration::from_millis(250));

    let group = run_dir(&temp, run_id).join("api/api-users");
    let case = wait_for_only_child(&group).await;
    for file in [
        "case-kind.json",
        "request.json",
        "baseline-response.json",
        "candidate-response.json",
    ] {
        assert!(case.join(file).is_file(), "missing {file}");
    }
    assert!(!case.join("comparison.json").exists());
    assert!(!case.join("dependencies.jsonl").exists());
    let kind = read_json(&case.join("case-kind.json"));
    assert_eq!(kind["kind"], "online_compare");
    assert_eq!(
        read_json(&case.join("baseline-response.json"))["status"],
        200
    );
    assert_eq!(
        read_json(&case.join("candidate-response.json"))["status"],
        200
    );
    task.abort();
}

#[tokio::test]
async fn case_limit_suppresses_files_but_keeps_mirroring() {
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, _) = spawn_counting_upstream(StatusCode::OK, "baseline", 2, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 2, None).await;
    let gateway = free_addr();
    let run_id = "20260722160001";
    let mut config = compare_config(&temp, gateway, baseline, candidate);
    config.http_gateway.case_limits.default = 1;
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    assert!(raw_get(gateway, "/api/one").await.contains("baseline"));
    assert!(raw_get(gateway, "/api/one").await.contains("baseline"));
    wait_for_counter(&candidate_requests, 2).await;
    let group = run_dir(&temp, run_id).join("api/api-one");
    let _ = wait_for_only_child(&group).await;
    assert_eq!(std::fs::read_dir(&group).unwrap().count(), 1);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("compare-run.json"),
        "suppressed_by_case_limit",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["dual_dispatched"], 2);
    assert_eq!(summary["apis"]["api:/api/one"]["last_baseline_status"], 200);
    assert_eq!(
        summary["apis"]["api:/api/one"]["last_candidate_status"],
        200
    );
    task.abort();
}

#[tokio::test]
async fn response_limit_preserves_baseline_and_records_partial_response() {
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("baseline-too-large", 1).await;
    let candidate = spawn_response_upstream("candidate", 1).await;
    let gateway = free_addr();
    let run_id = "20260722160002";
    let mut config = compare_config(&temp, gateway, baseline, candidate);
    config.compare.as_mut().unwrap().max_response_bytes = 8;
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    assert!(
        raw_get(gateway, "/api/large")
            .await
            .contains("baseline-too-large")
    );
    let case = wait_for_only_child(&run_dir(&temp, run_id).join("api/api-large")).await;
    let baseline = read_json(&case.join("baseline-response.json"));
    assert_eq!(baseline["status"], 200);
    assert_eq!(baseline["body"]["original_len"], 18);
    assert_eq!(baseline["body"]["stored_len"], 8);
    assert_eq!(baseline["body"]["truncated"], true);
    assert!(
        baseline["error"]
            .as_str()
            .unwrap()
            .contains("max_response_bytes")
    );
    task.abort();
}

#[tokio::test]
async fn unmatched_request_bypasses_compare_request_limit() {
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160007";
    let mut config = compare_config(&temp, gateway, baseline, candidate);
    config.compare.as_mut().unwrap().max_request_bytes = 4;
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    let response = raw_request(
        gateway,
        b"POST /health HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )
    .await;
    assert!(response.contains("baseline"));
    wait_for_counter(&baseline_requests, 1).await;
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn overload_forwards_only_to_baseline() {
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, _) = spawn_counting_upstream(StatusCode::OK, "baseline", 2, None).await;
    let (candidate, candidate_requests) = spawn_counting_upstream(
        StatusCode::OK,
        "candidate",
        1,
        Some(Duration::from_millis(300)),
    )
    .await;
    let gateway = free_addr();
    let run_id = "20260722160003";
    let mut config = compare_config(&temp, gateway, baseline, candidate);
    config.compare.as_mut().unwrap().max_in_flight = 1;
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    assert!(raw_get(gateway, "/api/one").await.contains("baseline"));
    assert!(raw_get(gateway, "/api/two").await.contains("baseline"));
    wait_for_counter(&candidate_requests, 1).await;
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("compare-run.json"),
        "overloaded",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["baseline_only"], 1);
    assert_eq!(summary["counts"]["dual_dispatched"], 1);
    task.abort();
}

#[tokio::test]
async fn request_limit_rejects_before_either_upstream() {
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160004";
    let mut config = compare_config(&temp, gateway, baseline, candidate);
    config.compare.as_mut().unwrap().max_request_bytes = 4;
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    let response = raw_request(
        gateway,
        b"GET /api/large HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )
    .await;
    assert!(response.contains("413 Payload Too Large"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(baseline_requests.load(Ordering::SeqCst), 0);
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 0);
    let _ = wait_for_count(
        &run_dir(&temp, run_id).join("compare-run.json"),
        "request_too_large",
        1,
    )
    .await;
    task.abort();
}

#[tokio::test]
async fn unmatched_request_forwards_only_to_baseline() {
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160005";
    let config = compare_config(&temp, gateway, baseline, candidate);
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;

    assert!(raw_get(gateway, "/health").await.contains("baseline"));
    wait_for_counter(&baseline_requests, 1).await;
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 0);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("compare-run.json"),
        "unmatched",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["baseline_only"], 1);
    task.abort();
}

#[tokio::test]
async fn not_ready_request_forwards_only_to_baseline() {
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 3, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::SERVICE_UNAVAILABLE, "candidate", 2, None).await;
    let gateway = free_addr();
    let run_id = "20260722160006";
    let mut config = compare_config(&temp, gateway, baseline, candidate);
    config.http_gateway.ready = HttpGatewayReadyConfig {
        enabled: true,
        path: "/".to_string(),
        success_status: 200,
        interval_ms: 1_000,
    };
    let task = tokio::spawn(traffic_e2e::run_compare(config, Some(run_id.to_string())));
    wait_for_port(gateway).await;
    wait_for_counter(&candidate_requests, 1).await;

    assert!(raw_get(gateway, "/api/one").await.contains("baseline"));
    wait_for_counter(&baseline_requests, 2).await;
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 1);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("compare-run.json"),
        "not_ready",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["baseline_only"], 1);
    task.abort();
}

fn install_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn compare_config(
    temp: &tempfile::TempDir,
    gateway: SocketAddr,
    baseline: SocketAddr,
    candidate: SocketAddr,
) -> AppConfig {
    let mut config = AppConfig {
        compare: Some(CompareConfig {
            baseline_upstream: format!("http://{baseline}"),
            candidate_upstream: format!("http://{candidate}"),
            upstream_timeout_ms: 2_000,
            summary_flush_interval_ms: 10,
            ..Default::default()
        }),
        ..Default::default()
    };
    config.http_gateway.listen = gateway;
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api".to_string()],
        ..Default::default()
    }];
    config.recording.output_dir = temp.path().join("recordings");
    config
}

async fn spawn_response_upstream(body: &'static str, count: usize) -> SocketAddr {
    spawn_counting_upstream(StatusCode::OK, body, count, None)
        .await
        .0
}

async fn spawn_delayed_upstream(body: &'static str, count: usize, delay: Duration) -> SocketAddr {
    spawn_counting_upstream(StatusCode::OK, body, count, Some(delay))
        .await
        .0
}

async fn spawn_counting_upstream(
    status: StatusCode,
    body: &'static str,
    count: usize,
    delay: Option<Duration>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    tokio::spawn(async move {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer).await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let response = format!(
                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown"),
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (address, requests)
}

async fn raw_get(address: SocketAddr, path: &str) -> String {
    raw_request(
        address,
        format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
}

async fn raw_request(address: SocketAddr, request: &[u8]) -> String {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn wait_for_port(address: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("port {address} did not open");
}

async fn wait_for_only_child(directory: &Path) -> PathBuf {
    for _ in 0..100 {
        if let Ok(entries) = std::fs::read_dir(directory) {
            let children = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect::<Vec<_>>();
            if children.len() == 1 {
                return children[0].clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("one child did not appear under {}", directory.display());
}

async fn wait_for_counter(counter: &AtomicUsize, expected: usize) {
    for _ in 0..100 {
        if counter.load(Ordering::SeqCst) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("counter did not reach {expected}");
}

async fn wait_for_count(path: &Path, field: &str, expected: u64) -> Value {
    for _ in 0..100 {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(report) = serde_json::from_slice::<Value>(&bytes)
            && report["counts"][field].as_u64() == Some(expected)
        {
            return report;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("summary field {field} did not reach {expected}");
}

fn run_dir(temp: &tempfile::TempDir, run_id: &str) -> PathBuf {
    temp.path().join("recordings/comparisons").join(run_id)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
