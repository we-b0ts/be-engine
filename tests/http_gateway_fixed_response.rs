use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_e2e::{
    AppConfig, AppState, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayReadyConfig, HttpGatewayRuleConfig,
};

#[tokio::test]
async fn fixed_response_handles_not_ready_excluded_and_unmatched_requests() {
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
        name: Some("record-api".to_string()),
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
    assert!(!run_dir.join("record-api").exists());
}

#[tokio::test]
async fn fixed_response_handles_concurrent_case_rejection_without_fallback_upstream() {
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
        name: Some("record-api".to_string()),
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
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
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

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .and_then(|listener| listener.local_addr())
        .expect("allocate free listen address")
}
