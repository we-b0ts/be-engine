use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use traffic_e2e::{
    AppConfig, AppState, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayReadyConfig, HttpGatewayRuleConfig,
};

// free_addr() cannot retain the socket while AppState binds the configured
// address. Keep tests in this binary exclusive during that handoff.
static PORT_BIND_TEST_LOCK: Mutex<()> = Mutex::const_new(());

#[tokio::test]
async fn fixed_response_handles_not_ready_excluded_and_unmatched_requests() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let matched_upstream =
        spawn_http_upstream("not-ready", "503 Service Unavailable", Duration::ZERO, None).await;
    let gateway_addr = free_addr();
    let mut config = fixed_response_config(
        &temp,
        gateway_addr,
        matched_upstream,
        201,
        r#"{"code":"fallback","msg":"fixed"}"#,
    );
    config.http_gateway.ready = HttpGatewayReadyConfig {
        enabled: true,
        path: "/ready".to_string(),
        success_status: 204,
        interval_ms: 20,
    };
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("http-rule".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        ..Default::default()
    }];
    config.http_gateway.exclude_rules = vec![HttpGatewayRuleConfig {
        name: Some("exclude-api".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/excluded".to_string()],
        ..Default::default()
    }];

    let state = AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    for path in ["/record/not-ready", "/excluded", "/other"] {
        let response = raw_http_get(gateway_addr, path).await;
        let normalized = response.to_ascii_lowercase();
        assert!(response.contains("201 Created"), "{response}");
        assert!(normalized.contains("content-type: application/json"));
        assert!(normalized.contains("x-recorder-fallback: fixed"));
        assert!(response.contains(r#"{"code":"fallback","msg":"fixed"}"#));
    }

    gateway.abort();
    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!run_dir.join("http-rule").exists());
}

#[tokio::test]
async fn exact_exclusion_returns_fixed_404_and_records_other_paths_and_methods() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let upstream = spawn_http_upstream("matched", "200 OK", Duration::ZERO, Some(4)).await;
    let gateway_addr = free_addr();
    let mut config = fixed_response_config(
        &temp,
        gateway_addr,
        upstream,
        404,
        r#"{"code":"not_recorded"}"#,
    );
    config.http_gateway.exclude_rules = vec![HttpGatewayRuleConfig {
        methods: vec!["GET".to_string()],
        paths: vec!["/api/jobs".to_string()],
        ..Default::default()
    }];
    let state = AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;
    for path in ["/api/jobs", "/api/jobs?limit=10"] {
        let response = raw_http_get(gateway_addr, path).await;
        assert!(response.contains("404 Not Found"), "{response}");
        assert!(response.contains(r#"{"code":"not_recorded"}"#));
    }
    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!run_dir.join("apis").exists());
    assert!(!run_dir.join("staging").exists());
    for (index, (method, path)) in [
        ("GET", "/api/jobs/42"),
        ("GET", "/api/jobs/"),
        ("GET", "/api/jobs-archive"),
        ("POST", "/api/jobs"),
    ]
    .into_iter()
    .enumerate()
    {
        let response = raw_http_request(gateway_addr, method, path, "", "").await;
        assert!(
            response.contains("200 OK") && response.ends_with("matched"),
            "{response}"
        );
        wait_for_case_counts(&run_dir, index + 1, 0).await;
    }
    let published_count: usize = std::fs::read_dir(run_dir.join("apis"))
        .unwrap()
        .map(|group| std::fs::read_dir(group.unwrap().path()).unwrap().count())
        .sum();
    assert_eq!(published_count, 4);
    gateway.abort();
}

#[tokio::test]
async fn fixed_response_handles_concurrent_case_rejection_without_fallback_upstream() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let matched_upstream =
        spawn_http_upstream("matched", "200 OK", Duration::from_millis(200), Some(1)).await;
    let gateway_addr = free_addr();
    let mut config = fixed_response_config(
        &temp,
        gateway_addr,
        matched_upstream,
        503,
        r#"{"code":"busy"}"#,
    );
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("http-rule".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        ..Default::default()
    }];

    let state = AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let first = tokio::spawn(raw_http_get(gateway_addr, "/record/one"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = raw_http_get(gateway_addr, "/record/two").await;
    assert!(second.contains("503 Service Unavailable"), "{second}");
    assert!(second.contains(r#"{"code":"busy"}"#));
    let first = first.await.unwrap();
    assert!(first.contains("200 OK"), "{first}");
    assert!(first.contains("matched"));

    gateway.abort();
}

#[tokio::test]
async fn matched_request_timeout_returns_gateway_timeout_and_retains_case_slot() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let matched_upstream = upstream.local_addr().unwrap();
    let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        complete_rx.await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo late")
            .await
            .unwrap();
    });
    let gateway_addr = free_addr();
    let mut config = fixed_response_config(
        &temp,
        gateway_addr,
        matched_upstream,
        201,
        r#"{\"code\":\"fallback\"}"#,
    );
    config.http_gateway.request_timeout_ms = 20;
    config.http_gateway.per_api_case_limits.default = 1;
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("http-rule".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        ..Default::default()
    }];

    let state = AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let response = raw_http_get(gateway_addr, "/record/first").await;
    assert!(response.contains("504 Gateway Timeout"), "{response}");
    assert!(response.contains("timed out after 20 ms"), "{response}");
    let response = raw_http_get(gateway_addr, "/record/second").await;
    assert!(response.contains("201 Created"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-recorder-fallback: fixed")
    );
    complete_tx.send(()).unwrap();
    source.await.unwrap();

    gateway.abort();
}

fn fixed_response_config(
    temp: &tempfile::TempDir,
    gateway_addr: SocketAddr,
    matched_upstream: SocketAddr,
    status: u16,
    body: &str,
) -> AppConfig {
    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
    config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
        status,
        content_type: Some("application/json".to_string()),
        headers: BTreeMap::from([("x-recorder-fallback".to_string(), "fixed".to_string())]),
        body: body.to_string(),
    });
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config
}

#[tokio::test]
async fn disabled_streaming_uses_fixed_fallback_before_dispatch_and_keeps_case_capacity() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = free_addr();
    let mut config = fixed_response_config(
        &temp,
        gateway_addr,
        source.local_addr().unwrap(),
        404,
        r#"{"code":"not_recorded"}"#,
    );
    config.http.enabled = false;
    assert!(!config.http_gateway.record_streaming);
    config.http_gateway.per_api_case_limits.default = 1;
    config.recording.case_dependency_post_response_window_ms = 0;
    let state = AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    for (method, accept) in [
        ("GET", "text/event-stream"),
        ("POST", "application/json, text/event-stream"),
        ("POST", "Text/Event-Stream; q=0"),
    ] {
        let response = raw_http_request(
            gateway_addr,
            method,
            "/api/mcp/knowledge/sse",
            &format!("Accept: {accept}\r\n"),
            r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#,
        )
        .await;
        assert!(response.contains("404 Not Found"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("x-recorder-fallback: fixed")
        );
        assert!(response.contains(r#"{"code":"not_recorded"}"#));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), source.accept())
            .await
            .is_err()
    );
    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!run_dir.join("apis").exists());
    assert!(!run_dir.join("staging").exists());
    assert!(!run_dir.join("failed").exists());

    let normal_source = tokio::spawn(async move {
        let (mut stream, _) = source.accept().await.unwrap();
        let mut request = [0; 2048];
        let size = stream.read(&mut request).await.unwrap();
        assert!(
            String::from_utf8_lossy(&request[..size])
                .to_ascii_lowercase()
                .contains("accept: application/json")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let response = raw_http_request(
        gateway_addr,
        "POST",
        "/api/mcp/knowledge/sse",
        "Accept: application/json\r\n",
        "{}",
    )
    .await;
    assert!(response.contains("200 OK"), "{response}");
    wait_for_case_counts(&run_dir, 1, 0).await;
    assert!(run_dir.join("apis/api-mcp-knowledge-sse").is_dir());
    normal_source.await.unwrap();
    gateway.abort();
}

#[tokio::test]
async fn disabled_streaming_uses_configured_fallback_upstream_without_recording() {
    let _port_bind_guard = PORT_BIND_TEST_LOCK.lock().await;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fallback = spawn_http_upstream("fallback", "200 OK", Duration::ZERO, Some(1)).await;
    let gateway_addr = free_addr();
    let mut config = fixed_response_config(
        &temp,
        gateway_addr,
        source.local_addr().unwrap(),
        404,
        "unused",
    );
    config.http.enabled = false;
    config.http_gateway.record_streaming = false;
    config.http_gateway.fallback_mode = HttpGatewayFallbackMode::Upstream;
    config.http_gateway.fixed_response = None;
    config.http_gateway.fallback_upstream = format!("http://{fallback}");
    let state = AppState::new(config).await.unwrap();
    let gateway = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;
    let response = raw_http_request(
        gateway_addr,
        "GET",
        "/api/events",
        "Accept: text/event-stream\r\n",
        "",
    )
    .await;
    assert!(
        response.contains("200 OK") && response.ends_with("fallback"),
        "{response}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), source.accept())
            .await
            .is_err()
    );
    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(!run_dir.join("apis").exists());
    assert!(!run_dir.join("failed").exists());
    gateway.abort();
}

async fn spawn_http_upstream(
    body: &'static str,
    status: &'static str,
    delay: Duration,
    accept_limit: Option<usize>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut accepted = 0_usize;
        loop {
            if accept_limit.is_some_and(|limit| accepted >= limit) {
                break;
            }
            let (mut stream, _) = listener.accept().await.unwrap();
            accepted += 1;
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    addr
}

async fn raw_http_get(addr: SocketAddr, path: &str) -> String {
    raw_http_request(addr, "GET", path, "", "").await
}

async fn raw_http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
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

async fn wait_for_case_counts(run_dir: &Path, published: usize, failed: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let report = std::fs::read(run_dir.join("recording-run.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
            if report.is_some_and(|report| {
                report["published_cases"] == published && report["failed_cases"] == failed
            }) {
                // Publication and admission release finish in the owner's next poll.
                tokio::task::yield_now().await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordinary HTTP case must finish asynchronous publication");
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .and_then(|listener| listener.local_addr())
        .expect("allocate free listen address")
}
