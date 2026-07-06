use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_recorder_proxy::{AppConfig, HttpGatewayRuleConfig, MysqlRouteConfig};

#[tokio::test]
async fn records_http_proxy_exchange() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .unwrap();
    });

    let proxy_addr = free_addr();
    let mut config = AppConfig::default();
    config.http.enabled = true;
    config.http.listen = proxy_addr;
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(proxy_addr).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/hello HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("hello"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let jsonl = tokio::fs::read_to_string(temp.path().join("recordings/traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"http_exchange""#));
    assert!(jsonl.contains(r#""method":"GET""#));
}

#[tokio::test]
async fn http_gateway_records_only_matched_traffic() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream = spawn_http_response_upstream("matched", 1).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("record-path".to_string()),
        hosts: Vec::new(),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        headers: Default::default(),
    }];
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let matched_response = raw_http_get(gateway_addr, "/record").await;
    assert!(matched_response.contains("matched"));
    let fallback_response = raw_http_get(gateway_addr, "/recording/two").await;
    assert!(fallback_response.contains("fallback"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let jsonl = tokio::fs::read_to_string(temp.path().join("recordings/traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"http_exchange""#));
    assert!(jsonl.contains("/record"));
    assert!(!jsonl.contains("/recording/two"));
}

#[tokio::test]
async fn http_gateway_writes_case_files_and_decodes_gzip_response() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream = spawn_http_gzip_response_upstream(r#"{"ok":true}"#).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".to_string()),
        hosts: Vec::new(),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api/".to_string()],
        headers: Default::default(),
    }];
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let response = raw_http_get(gateway_addr, "/api").await;
    assert!(response.contains("Content-Encoding: gzip"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let rule_dir = temp.path().join("recordings/api");
    let case_dirs = std::fs::read_dir(&rule_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(case_dirs.len(), 1);
    let case_dir = &case_dirs[0];

    let request_json = std::fs::read_to_string(case_dir.join("request.json")).unwrap();
    assert!(request_json.contains(r#""uri": "/api""#));

    let response_json = std::fs::read_to_string(case_dir.join("expected-response.json")).unwrap();
    let response: Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["status"], 200);
    assert_eq!(response["body"]["encoding"], "utf8");
    assert_eq!(response["body"]["decoded"], true);
    assert_eq!(response["body"]["content_encoding"], "gzip");
    assert_eq!(response["body"]["data"], r#"{"ok":true}"#);
}

#[tokio::test]
async fn records_and_rejects_mysql_tls_request() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().await.unwrap();
            stream
                .write_all(&mysql_packet(0, mysql_handshake_payload().as_slice()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let proxy_addr = free_addr();
    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.mysql.enabled = true;
    config.mysql.listen = proxy_addr;
    config.mysql.upstream = upstream_addr.to_string();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(proxy_addr).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await.unwrap();
    let payload_len =
        header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0_u8; payload_len];
    client.read_exact(&mut payload).await.unwrap();

    let mut ssl_request = vec![0_u8; 32];
    ssl_request[0..4].copy_from_slice(&0x0000_8800_u32.to_le_bytes());
    client
        .write_all(&mysql_packet(1, ssl_request.as_slice()))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.abort();

    let jsonl = tokio::fs::read_to_string(temp.path().join("recordings/traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"mysql_tls_rejected""#));
}

#[tokio::test]
async fn supports_multiple_mysql_routes_on_same_port_with_different_ips() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let master_upstream = spawn_mysql_handshake_upstream(1).await;
    let slave_upstream = spawn_mysql_handshake_upstream(1).await;
    let (master_listen, slave_listen) = free_same_port_loopback_pair();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.mysql.enabled = true;
    config.mysql.routes = vec![
        MysqlRouteConfig {
            name: Some("master".to_string()),
            listen: master_listen,
            upstream: master_upstream.to_string(),
        },
        MysqlRouteConfig {
            name: Some("slave".to_string()),
            listen: slave_listen,
            upstream: slave_upstream.to_string(),
        },
    ];
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(master_listen).await;
    wait_for_port(slave_listen).await;
    handle.abort();
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn free_same_port_loopback_pair() -> (SocketAddr, SocketAddr) {
    for _ in 0..100 {
        let port = free_addr().port();
        let master = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port);
        let slave = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), port);
        let Ok(master_probe) = std::net::TcpListener::bind(master) else {
            continue;
        };
        let Ok(slave_probe) = std::net::TcpListener::bind(slave) else {
            continue;
        };
        drop(master_probe);
        drop(slave_probe);
        return (master, slave);
    }
    panic!("failed to find a free same-port loopback pair");
}

async fn spawn_http_response_upstream(body: &'static str, accept_count: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..accept_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    addr
}

async fn spawn_http_gzip_response_upstream(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, body.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            compressed.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&compressed).await.unwrap();
    });
    addr
}

async fn spawn_mysql_handshake_upstream(accept_count: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..accept_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(&mysql_packet(0, mysql_handshake_payload().as_slice()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
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
    String::from_utf8_lossy(&response).to_string()
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

fn mysql_packet(sequence_id: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push((len & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(sequence_id);
    out.extend_from_slice(payload);
    out
}

fn mysql_handshake_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x0a);
    payload.extend_from_slice(b"8.0.0-test\0");
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(b"abcdefgh");
    payload.push(0);
    payload.extend_from_slice(&0xffff_u16.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&0xffff_u16.to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0_u8; 10]);
    payload.extend_from_slice(b"ijklmnopqrstuvwxyz\0");
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}
