use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_e2e::{
    AppConfig, HttpGatewayRuleConfig, MysqlRouteConfig, MysqlWriteOperation, RecordingAccessPolicy,
    RecordingAccessRuleConfig, RecordingAccessRuleEffect,
};

#[tokio::test]
async fn rejected_http_dependency_invalidates_active_gateway_case() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let proxy_addr = free_addr();
    let gateway_addr = free_addr();
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
    let failed_group = run_dir.join("failed/readonly/scenario-readonly");
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
    assert_eq!(report["status"], "failed");
    assert_eq!(report["published_cases"], 0);
    assert_eq!(report["failed_cases"], 1);
}

#[tokio::test]
async fn mysql_query_inside_post_response_window_stays_with_case_and_late_query_does_not() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let mysql_proxy_addr = free_addr();
    let mysql_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mysql_upstream_addr = mysql_upstream.local_addr().unwrap();
    let mysql_upstream_task = tokio::spawn(async move {
        let (mut stream, _) = mysql_upstream.accept().await.unwrap();
        write_mysql_packet(&mut stream, 0, &[0x0a]).await;
        let login = read_mysql_packet(&mut stream).await.unwrap();
        assert_eq!(login.0, 1);
        write_mysql_packet(&mut stream, 2, &[0x00]).await;

        for expected in [
            "INSERT INTO request_log(message) VALUES ('gateway-get')",
            "INSERT INTO request_log(message) VALUES ('background-after-window')",
        ] {
            let query = read_mysql_packet(&mut stream).await.unwrap();
            assert_eq!(query.0, 0);
            assert_eq!(query.1[0], 0x03);
            assert_eq!(String::from_utf8_lossy(&query.1[1..]), expected);
            write_mysql_packet(&mut stream, 1, &[0x00]).await;
        }
    });

    let matched = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let matched_addr = matched.local_addr().unwrap();
    let matched_task = tokio::spawn(async move {
        let (mut stream, _) = matched.accept().await.unwrap();
        let gateway_request = read_http_request(&mut stream).await;
        assert!(gateway_request.starts_with("GET /scenario/mysql-log "));

        let mut mysql = connect_with_retry(mysql_proxy_addr).await;
        assert!(read_mysql_packet(&mut mysql).await.is_some());
        write_mysql_packet(&mut mysql, 1, &mysql_login_payload("pluto")).await;
        assert_eq!(read_mysql_packet(&mut mysql).await.unwrap().1[0], 0x00);
        let sql = b"INSERT INTO request_log(message) VALUES ('gateway-get')";
        let mut query = vec![0x03];
        query.extend_from_slice(sql);
        write_http_response(&mut stream, r#"{"ok":true}"#).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_mysql_packet(&mut mysql, 0, &query).await;
        assert_eq!(read_mysql_packet(&mut mysql).await.unwrap().1[0], 0x00);

        tokio::time::sleep(Duration::from_millis(150)).await;
        let background_sql = b"INSERT INTO request_log(message) VALUES ('background-after-window')";
        let mut background_query = vec![0x03];
        background_query.extend_from_slice(background_sql);
        write_mysql_packet(&mut mysql, 0, &background_query).await;
        assert_eq!(read_mysql_packet(&mut mysql).await.unwrap().1[0], 0x00);
    });

    let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = free_addr();
    let mut config = AppConfig::default();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_addr}");
    config.http_gateway.fallback_upstream = format!("http://{}", fallback.local_addr().unwrap());
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("mysql-log".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/scenario/mysql-log".to_string()],
        ..Default::default()
    }];
    config.mysql.enabled = true;
    config.mysql.routes = vec![MysqlRouteConfig {
        name: Some("audit-db".to_string()),
        listen: mysql_proxy_addr,
        upstream: mysql_upstream_addr.to_string(),
    }];
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
    config.recording.access_rules = vec![RecordingAccessRuleConfig::Mysql {
        name: "allow-request-log".to_string(),
        effect: RecordingAccessRuleEffect::Allow,
        operations: vec![MysqlWriteOperation::Insert],
        routes: vec!["audit-db".to_string()],
        targets: Vec::new(),
        databases: vec!["pluto".to_string()],
        tables: vec!["request_log".to_string()],
    }];
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_e2e::AppState::new(config).await.unwrap();
    let recorder = state.recorder().clone();
    let recorder_task = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let response = send_http_request(
        gateway_addr,
        "GET /scenario/mysql-log HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            .to_string(),
    )
    .await;
    assert!(response.contains("200 OK"));
    matched_task.await.unwrap();
    mysql_upstream_task.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    recorder_task.abort();
    recorder.flush_traffic().await.unwrap();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    assert!(!run_dir.join("failed").exists());
    let published_group = run_dir.join("mysql-log/scenario-mysql-log");
    let published_cases = std::fs::read_dir(&published_group)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(published_cases.len(), 1);
    let published_case = &published_cases[0];
    assert!(published_case.join("request.json").exists());
    assert!(published_case.join("expected-response.json").exists());

    let dependencies = read_json_lines(&published_case.join("dependencies.jsonl"));
    assert!(dependencies.iter().any(|event| {
        event["event_type"] == "mysql_exchange"
            && event["database"] == "pluto"
            && event["sql"] == "INSERT INTO request_log(message) VALUES ('gateway-get')"
    }));
    assert!(!dependencies.iter().any(|event| {
        event["event_type"] == "mysql_exchange"
            && event["sql"] == "INSERT INTO request_log(message) VALUES ('background-after-window')"
    }));
    assert!(
        !dependencies
            .iter()
            .any(|event| event["event_type"] == "access_policy_allow")
    );
    assert!(
        !dependencies
            .iter()
            .any(|event| event["event_type"] == "readonly_rejection")
    );

    let traffic = read_json_lines(&run_dir.join("traffic.jsonl"));
    assert!(traffic.iter().any(|event| {
        event["event_type"] == "access_policy_allow"
            && event["rule"] == "allow-request-log"
            && event["resources"] == serde_json::json!(["pluto.request_log"])
    }));
    assert!(traffic.iter().any(|event| {
        event["event_type"] == "mysql_exchange"
            && event["sql"] == "INSERT INTO request_log(message) VALUES ('background-after-window')"
    }));
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("recording-run.json")).unwrap())
            .unwrap();
    assert_eq!(report["published_cases"], 1);
    assert_eq!(report["failed_cases"], 0);
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

async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
    for _ in 0..100 {
        match TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("port {addr} did not accept a connection");
}

async fn read_mysql_packet(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0_u8; 4];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
        Err(error) => panic!("failed to read MySQL packet header: {error}"),
    }
    let len = header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    Some((header[3], payload))
}

async fn write_mysql_packet(stream: &mut TcpStream, sequence_id: u8, payload: &[u8]) {
    let len = payload.len();
    let header = [
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        sequence_id,
    ];
    stream.write_all(&header).await.unwrap();
    stream.write_all(payload).await.unwrap();
}

fn mysql_login_payload(database: &str) -> Vec<u8> {
    let mut payload = vec![0_u8; 32];
    payload[0..4].copy_from_slice(&0x0000_0008_u32.to_le_bytes());
    payload.extend_from_slice(b"integration-test\0");
    payload.push(0);
    payload.extend_from_slice(database.as_bytes());
    payload.push(0);
    payload
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
