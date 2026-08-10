use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use hyper::StatusCode;
use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use traffic_e2e::{
    AppConfig, ArtifactsConfig, ComparisonRecordingConfig, ComparisonRecordingRunOptions,
    HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig, HttpGatewayReadyConfig,
    HttpGatewayRuleConfig, RecordingWaitConfig, notify_recording_input_complete,
    wait_for_recording_ready,
};

// Config accepts concrete listen addresses, so free_addr() releases its socket
// before the runtime binds it. Keep these integration tests exclusive to close
// that port-reuse race while preserving parallelism in the rest of the suite.
static PORT_BIND_TEST_LOCK: Mutex<()> = Mutex::const_new(());

#[tokio::test]
async fn decodes_gzip_response_artifacts_without_changing_the_forwarded_response() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let body = r#"{"ok":true,"source":"same"}"#;
    let baseline = spawn_gzip_response_upstream(body, 1).await;
    let candidate = spawn_response_upstream(body, 1).await;
    let gateway = free_addr();
    let run_id = "20260722155958";
    let config = comparison_recording_config(&temp, gateway, baseline, candidate);
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    let response = raw_request_bytes(
        gateway,
        b"GET /api/gzip HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let body_offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .unwrap();
    assert!(
        String::from_utf8_lossy(&response[..body_offset])
            .to_ascii_lowercase()
            .contains("content-encoding: gzip")
    );
    let mut decoder = GzDecoder::new(&response[body_offset..]);
    let mut forwarded_body = String::new();
    decoder.read_to_string(&mut forwarded_body).unwrap();
    assert_eq!(forwarded_body, body);

    let case = wait_for_only_child(&run_dir(&temp, run_id).join("api/api-gzip")).await;
    let expected = read_json(&case.join("expected-response.json"));
    assert_eq!(expected["body"]["encoding"], "utf8");
    assert_eq!(expected["body"]["decoded"], true);
    assert_eq!(expected["body"]["content_encoding"], "gzip");
    assert_eq!(expected["body"]["data"], body);
    assert_eq!(expected["body"]["decode_error"], Value::Null);

    let actual = read_json(&case.join("response.json"));
    assert_eq!(actual["body"]["encoding"], "utf8");
    assert_eq!(actual["body"]["decoded"], false);
    assert_eq!(actual["body"]["content_encoding"], Value::Null);
    assert_eq!(actual["body"]["data"], body);
    task.abort();
}

#[tokio::test]
async fn duration_stops_cleanly_after_comparison_recording_is_ready() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("ready", 2).await;
    let candidate = spawn_status_sequence_upstream(vec![
        (StatusCode::SERVICE_UNAVAILABLE, "not-ready"),
        (StatusCode::OK, "ready"),
    ])
    .await;
    let gateway = free_addr();
    let run_id = "20260722155959";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.http_gateway.ready = HttpGatewayReadyConfig {
        enabled: true,
        path: "/".to_string(),
        success_status: 200,
        interval_ms: 100,
    };
    let started = Instant::now();
    let control_socket = temp.path().join("comparison.sock");

    let task = tokio::spawn(traffic_e2e::run_comparison_recording_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id: Some(run_id.to_string()),
            duration: Some(Duration::from_millis(250)),
            recording_apis: Vec::new(),
            control_socket: Some(control_socket.clone()),
        },
    ));
    let readiness = wait_for_recording_ready(RecordingWaitConfig {
        control_socket_path: control_socket,
        timeout: Duration::from_secs(1),
    })
    .await
    .unwrap();
    assert!(readiness.ready);
    task.await.unwrap().unwrap();

    assert!(started.elapsed() >= Duration::from_millis(100));
    let summary = read_json(&run_dir(&temp, run_id).join("comparison-recording-run.json"));
    assert_eq!(summary["status"], "completed");
    assert_eq!(summary["ready"], true);
}

#[tokio::test]
async fn finite_input_completion_stops_before_duration_after_the_case_is_published() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("baseline", 1).await;
    let candidate = spawn_response_upstream("candidate", 1).await;
    let gateway = free_addr();
    let run_id = "20260722155960";
    let config = comparison_recording_config(&temp, gateway, baseline, candidate);
    let control_socket = temp.path().join("comparison.sock");
    let task = tokio::spawn(traffic_e2e::run_comparison_recording_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id: Some(run_id.to_string()),
            duration: Some(Duration::from_secs(5)),
            recording_apis: Vec::new(),
            control_socket: Some(control_socket.clone()),
        },
    ));
    wait_for_recording_ready(RecordingWaitConfig {
        control_socket_path: control_socket.clone(),
        timeout: Duration::from_secs(1),
    })
    .await
    .unwrap();

    assert!(raw_get(gateway, "/api/finite").await.contains("baseline"));
    notify_recording_input_complete(&control_socket, 1)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("finite input completion should not wait for the five-second duration")
        .unwrap()
        .unwrap();

    let summary = read_json(&run_dir(&temp, run_id).join("comparison-recording-run.json"));
    assert_eq!(summary["status"], "completed");
    assert_eq!(summary["completion_reason"], "input_exhausted");
    assert_eq!(summary["counts"]["published"], 1);
}

#[tokio::test]
async fn finite_input_completion_rejects_missing_published_cases() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("baseline", 1).await;
    let candidate = spawn_response_upstream("candidate", 1).await;
    let gateway = free_addr();
    let run_id = "20260722160009";
    let config = comparison_recording_config(&temp, gateway, baseline, candidate);
    let control_socket = temp.path().join("comparison.sock");
    let task = tokio::spawn(traffic_e2e::run_comparison_recording_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id: Some(run_id.to_string()),
            duration: Some(Duration::from_secs(5)),
            recording_apis: Vec::new(),
            control_socket: Some(control_socket.clone()),
        },
    ));
    wait_for_recording_ready(RecordingWaitConfig {
        control_socket_path: control_socket.clone(),
        timeout: Duration::from_secs(1),
    })
    .await
    .unwrap();

    assert!(raw_get(gateway, "/api/finite").await.contains("baseline"));
    notify_recording_input_complete(&control_socket, 2)
        .await
        .unwrap();
    task.await.unwrap().unwrap();

    let summary = read_json(&run_dir(&temp, run_id).join("comparison-recording-run.json"));
    assert_eq!(summary["status"], "completed_with_errors");
    assert_eq!(summary["completion_reason"], "input_exhausted");
    assert!(
        summary["errors"][0]
            .as_str()
            .unwrap()
            .contains("delivered 2 request template(s), but only 1")
    );
}

#[tokio::test]
async fn returns_baseline_after_the_serial_comparison_case_is_complete() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("baseline", 2).await;
    let candidate = spawn_delayed_upstream("candidate", 1, Duration::from_millis(300)).await;
    let gateway = free_addr();
    let run_id = "20260722160000";
    let config = comparison_recording_config(&temp, gateway, baseline, candidate);
    let task = tokio::spawn(traffic_e2e::run_comparison_recording_with_options(
        config,
        ComparisonRecordingRunOptions {
            run_id: Some(run_id.to_string()),
            duration: None,
            recording_apis: vec!["GET /api/users/*".parse().unwrap()],
            control_socket: None,
        },
    ));
    wait_for_port(gateway).await;

    let started = Instant::now();
    assert!(raw_get(gateway, "/api/users/42").await.contains("baseline"));
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(raw_get(gateway, "/api/ignored").await.contains("fixed"));

    let group = run_dir(&temp, run_id).join("api/api-users-wildcard");
    let case = wait_for_only_child(&group).await;
    for file in [
        "case-kind.json",
        "request.json",
        "expected-response.json",
        "response.json",
    ] {
        assert!(case.join(file).is_file(), "missing {file}");
    }
    assert!(!case.join("comparison.json").exists());
    assert!(!case.join("dependencies.jsonl").exists());
    let kind = read_json(&case.join("case-kind.json"));
    assert_eq!(kind["kind"], "comparison_recording");
    assert_eq!(
        read_json(&case.join("request.json"))["api_pattern"],
        "/api/users/*"
    );
    assert_eq!(
        read_json(&case.join("expected-response.json"))["status"],
        200
    );
    assert_eq!(read_json(&case.join("response.json"))["status"], 200);
    assert!(!case.join("expected-response-after.json").exists());
    assert!(!run_dir(&temp, run_id).join("api/api-ignored").exists());
    assert_eq!(
        read_json(&run_dir(&temp, run_id).join("comparison-recording-run.json"))["recording_apis"],
        serde_json::json!(["GET /api/users/*"])
    );
    task.abort();
}

#[tokio::test]
async fn optional_baseline_recheck_records_source_candidate_source_in_order() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_status_sequence_upstream(vec![
        (StatusCode::OK, "baseline-before"),
        (StatusCode::OK, "baseline-after"),
    ])
    .await;
    let candidate = spawn_response_upstream("candidate", 1).await;
    let gateway = free_addr();
    let run_id = "20260722160008";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config
        .comparison_recording
        .as_mut()
        .unwrap()
        .baseline_recheck = true;
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    assert!(
        raw_get(gateway, "/api/recheck")
            .await
            .contains("baseline-before")
    );
    let case = wait_for_only_child(&run_dir(&temp, run_id).join("api/api-recheck")).await;
    assert_eq!(
        recorded_body(&case.join("expected-response.json")),
        "baseline-before"
    );
    assert_eq!(recorded_body(&case.join("response.json")), "candidate");
    assert_eq!(
        recorded_body(&case.join("expected-response-after.json")),
        "baseline-after"
    );
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("comparison-recording-run.json"),
        "baseline_recheck_success",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["candidate_success"], 1);
    task.abort();
}

#[tokio::test]
async fn case_limit_returns_fixed_response_without_more_mirroring() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160001";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.http_gateway.per_api_case_limits.default = 1;
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    assert!(raw_get(gateway, "/api/one").await.contains("baseline"));
    assert!(raw_get(gateway, "/api/one").await.contains("fixed"));
    wait_for_counter(&candidate_requests, 1).await;
    assert_eq!(baseline_requests.load(Ordering::SeqCst), 1);
    let group = run_dir(&temp, run_id).join("api/api-one");
    let _ = wait_for_only_child(&group).await;
    assert_eq!(std::fs::read_dir(&group).unwrap().count(), 1);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("comparison-recording-run.json"),
        "suppressed_by_case_limit",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["dual_dispatched"], 1);
    assert_eq!(summary["counts"]["fixed_response"], 1);
    assert_eq!(summary["counts"]["baseline_only"], 0);
    assert_eq!(summary["apis"]["api:/api/one"]["last_baseline_status"], 200);
    assert_eq!(
        summary["apis"]["api:/api/one"]["last_candidate_status"],
        200
    );
    task.abort();
}

#[tokio::test]
async fn response_limit_preserves_baseline_and_records_partial_response() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let baseline = spawn_response_upstream("baseline-too-large", 1).await;
    let candidate = spawn_response_upstream("candidate", 1).await;
    let gateway = free_addr();
    let run_id = "20260722160002";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.recording.max_body_bytes = 8;
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    assert!(
        raw_get(gateway, "/api/large")
            .await
            .contains("baseline-too-large")
    );
    let case = wait_for_only_child(&run_dir(&temp, run_id).join("api/api-large")).await;
    let baseline = read_json(&case.join("expected-response.json"));
    assert_eq!(baseline["status"], 200);
    assert_eq!(baseline["body"]["original_len"], 18);
    assert_eq!(baseline["body"]["stored_len"], 8);
    assert_eq!(baseline["body"]["truncated"], true);
    assert!(
        baseline["error"]
            .as_str()
            .unwrap()
            .contains("recording.max_body_bytes")
    );
    task.abort();
}

#[tokio::test]
async fn unconfigured_post_is_not_mirrored() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160007";
    let config = comparison_recording_config(&temp, gateway, baseline, candidate);
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    let response = raw_request(
        gateway,
        b"POST /api/write HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )
    .await;
    assert!(response.contains("fixed"));
    assert_eq!(baseline_requests.load(Ordering::SeqCst), 0);
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn configured_post_is_mirrored_to_both_upstreams() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160008";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.http_gateway.rules[0].methods = vec!["POST".to_string()];
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    let response = raw_request(
        gateway,
        b"POST /api/write HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )
    .await;
    assert!(response.contains("baseline"));
    wait_for_counter(&baseline_requests, 1).await;
    wait_for_counter(&candidate_requests, 1).await;
    task.abort();
}

#[tokio::test]
async fn overload_returns_fixed_response_without_single_sided_dispatch() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) = spawn_counting_upstream(
        StatusCode::OK,
        "candidate",
        1,
        Some(Duration::from_millis(300)),
    )
    .await;
    let gateway = free_addr();
    let run_id = "20260722160003";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.comparison_recording.as_mut().unwrap().max_in_flight = 1;
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    let first = tokio::spawn(raw_get(gateway, "/api/one"));
    wait_for_counter(&baseline_requests, 1).await;
    assert!(raw_get(gateway, "/api/two").await.contains("fixed"));
    assert!(first.await.unwrap().contains("baseline"));
    wait_for_counter(&candidate_requests, 1).await;
    assert_eq!(baseline_requests.load(Ordering::SeqCst), 1);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("comparison-recording-run.json"),
        "overloaded",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["fixed_response"], 1);
    assert_eq!(summary["counts"]["dual_dispatched"], 1);
    task.abort();
}

#[tokio::test]
async fn request_limit_rejects_before_either_upstream() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160004";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.recording.max_body_bytes = 4;
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
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
        &run_dir(&temp, run_id).join("comparison-recording-run.json"),
        "request_too_large",
        1,
    )
    .await;
    task.abort();
}

#[tokio::test]
async fn unmatched_request_returns_fixed_response_without_upstream_dispatch() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 1, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::OK, "candidate", 1, None).await;
    let gateway = free_addr();
    let run_id = "20260722160005";
    let config = comparison_recording_config(&temp, gateway, baseline, candidate);
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;

    assert!(raw_get(gateway, "/health").await.contains("fixed"));
    assert_eq!(baseline_requests.load(Ordering::SeqCst), 0);
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 0);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("comparison-recording-run.json"),
        "unmatched",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["fixed_response"], 1);
    task.abort();
}

#[tokio::test]
async fn not_ready_request_returns_fixed_response_without_single_sided_dispatch() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    install_crypto();
    let temp = tempdir().unwrap();
    let (baseline, baseline_requests) =
        spawn_counting_upstream(StatusCode::OK, "baseline", 3, None).await;
    let (candidate, candidate_requests) =
        spawn_counting_upstream(StatusCode::SERVICE_UNAVAILABLE, "candidate", 2, None).await;
    let gateway = free_addr();
    let run_id = "20260722160006";
    let mut config = comparison_recording_config(&temp, gateway, baseline, candidate);
    config.http_gateway.ready = HttpGatewayReadyConfig {
        enabled: true,
        path: "/".to_string(),
        success_status: 200,
        interval_ms: 1_000,
    };
    let task = tokio::spawn(traffic_e2e::run_comparison_recording(
        config,
        Some(run_id.to_string()),
    ));
    wait_for_port(gateway).await;
    wait_for_counter(&candidate_requests, 1).await;

    assert!(raw_get(gateway, "/api/one").await.contains("fixed"));
    assert_eq!(baseline_requests.load(Ordering::SeqCst), 1);
    assert_eq!(candidate_requests.load(Ordering::SeqCst), 1);
    let summary = wait_for_count(
        &run_dir(&temp, run_id).join("comparison-recording-run.json"),
        "not_ready",
        1,
    )
    .await;
    assert_eq!(summary["counts"]["fixed_response"], 1);
    task.abort();
}

fn install_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn comparison_recording_config(
    temp: &tempfile::TempDir,
    gateway: SocketAddr,
    baseline: SocketAddr,
    candidate: SocketAddr,
) -> AppConfig {
    let mut config = AppConfig {
        comparison_recording: Some(ComparisonRecordingConfig {
            candidate_upstream: format!("http://{candidate}"),
            upstream_timeout_ms: 2_000,
            summary_flush_interval_ms: 10,
            ..Default::default()
        }),
        artifacts: Some(ArtifactsConfig {
            root_dir: temp.path().join("artifacts"),
        }),
        ..Default::default()
    };
    config.http_gateway.listen = gateway;
    config.http_gateway.matched_upstream = format!("http://{baseline}");
    config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
    config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
        status: 200,
        body: "fixed".to_string(),
        ..Default::default()
    });
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api".to_string()],
        ..Default::default()
    }];
    config
}

async fn spawn_response_upstream(body: &'static str, count: usize) -> SocketAddr {
    spawn_counting_upstream(StatusCode::OK, body, count, None)
        .await
        .0
}

async fn spawn_gzip_response_upstream(body: &'static str, count: usize) -> SocketAddr {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer).await.unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                compressed.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&compressed).await.unwrap();
        }
    });
    address
}

async fn spawn_delayed_upstream(body: &'static str, count: usize, delay: Duration) -> SocketAddr {
    spawn_counting_upstream(StatusCode::OK, body, count, Some(delay))
        .await
        .0
}

async fn spawn_status_sequence_upstream(responses: Vec<(StatusCode, &'static str)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer).await.unwrap();
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
    address
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
    String::from_utf8_lossy(&raw_request_bytes(address, request).await).into_owned()
}

async fn raw_request_bytes(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
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
    temp.path()
        .join("artifacts/comparison-recordings")
        .join(run_id)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn recorded_body(path: &Path) -> String {
    let response = read_json(path);
    let body = &response["body"];
    match body["encoding"].as_str().unwrap() {
        "utf8" => body["data"].as_str().unwrap().to_string(),
        "base64" => {
            String::from_utf8(STANDARD.decode(body["data"].as_str().unwrap()).unwrap()).unwrap()
        }
        encoding => panic!("unexpected recording body encoding {encoding}"),
    }
}
