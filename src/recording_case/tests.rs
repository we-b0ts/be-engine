//! Genuine HTTP and Redis peers exercise primary selection and delayed capture.
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{AppConfig, AppState, BackgroundDependencyRuleConfig, HttpGatewayRuleConfig};

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), accepted.unwrap().0)
}

async fn head(socket: &mut TcpStream) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(socket.read_u8().await.unwrap());
    }
}

#[tokio::test]
async fn background_api_delivers_response_then_records_a_delayed_real_redis_request() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = AppConfig::default();
        config.http_gateway.enabled = true;
        config.http_gateway.matched_upstream = format!("http://{}", source.local_addr().unwrap());
        config.http_gateway.request_timeout_ms = 2_000;
        config.http_gateway.rules = vec![HttpGatewayRuleConfig {
            name: Some("jobs".into()), methods: vec!["POST".into()], paths: vec!["/jobs".into()], ..Default::default()
        }];
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.case_dependency_post_response_window_ms = 5;
        config.recording.api_origin_dependency_idle_ms = 100;
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let rule: BackgroundDependencyRuleConfig = serde_json::from_value(serde_json::json!({
            "protocol": "redis", "name": "job-cancel", "ports": [6379], "command": "GET",
            "key_templates": ["cancel:{task_id}"], "source_revision": "a".repeat(64),
            "source_evidence": "app/jobs.rs:1 detached job cancellation check",
            "trigger_source": {
                "kind": "api", "method": "POST", "path": "/jobs", "request_body_json": {"/background": true},
                "capture": {"task_id": {
                    "protocol": "mysql", "target_host": "mysql.test", "target_port": 3306,
                    "database": "jobs", "username": "app", "operation": "INSERT",
                    "tables": ["tasks"], "row_match": {"kind": "Task"}, "column": "id"
                }}
            }
        })).unwrap();
        config.process_owned_dependencies = vec![rule];
        let state = AppState::new(config).await.unwrap();
        let (mut source_redis, redis_client) = pair().await;
        let (mut redis_server, redis_upstream) = pair().await;
        let redis = tokio::spawn(crate::recorder::redis::handle_connected(
            redis_client, redis_upstream, state.clone(), crate::recorder::redis::ConnectionContext {
                client_addr: None, target_host: "redis.test".into(), target_port: 6379,
                target_addr: "redis.test:6379".into(), upstream_addr: "redis.test:6379".into(),
            },
        ));
        let (send_dependency, after_response) = tokio::sync::oneshot::channel();
        let source_task = tokio::spawn(async move {
            let (mut socket, _) = source.accept().await.unwrap();
            head(&mut socket).await;
            let mut body = vec![0; br#"{"background":true}"#.len()];
            socket.read_exact(&mut body).await.unwrap();
            assert_eq!(body, br#"{"background":true}"#);
            socket.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
            socket.shutdown().await.unwrap();
            after_response.await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            source_redis.write_all(b"*2\r\n$3\r\nGET\r\n$9\r\ncancel:42\r\n").await.unwrap();
            let mut response = [0; 5];
            source_redis.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"$-1\r\n");
        });
        let upstream_task = tokio::spawn(async move {
            let mut command = vec![0; b"*2\r\n$3\r\nGET\r\n$9\r\ncancel:42\r\n".len()];
            redis_server.read_exact(&mut command).await.unwrap();
            assert!(command.ends_with(b"cancel:42\r\n"));
            // A slow selected request must remain in flight beyond one idle window.
            tokio::time::sleep(Duration::from_millis(120)).await;
            redis_server.write_all(b"$-1\r\n").await.unwrap();
        });
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = gateway.local_addr().unwrap();
        let gateway_task = tokio::spawn(crate::gateway::http::run_with_listener(state.clone(), gateway));
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"POST /jobs HTTP/1.1\r\nHost: source.test\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"background\":true}").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_millis(500), client.read_to_end(&mut response)).await.unwrap().unwrap();
        assert!(response.starts_with(b"HTTP/1.1 202"));
        assert!(response.ends_with(b"ok"));
        let case = state.capture_dependency_targets().cases[0].0.clone();
        assert!(!state.recorder().case_dir(&case).exists());
        send_dependency.send(()).unwrap();
        source_task.await.unwrap();
        upstream_task.await.unwrap();
        assert!(state.inner.active_cases.wait_for_no_active_case(Duration::from_secs(2)).await);
        let directory = state.recorder().case_dir(&case);
        let report: serde_json::Value = serde_json::from_slice(&tokio::fs::read(directory.join("api-origin-observation.json")).await.unwrap()).unwrap();
        assert_eq!(report["outcome"], "quiet");
        assert_eq!(report["selected_completed_refs"].as_array().unwrap().len(), 1);
        assert_eq!(report["rules"][0]["selected_selector_only"], 1);
        let dependencies = tokio::fs::read_to_string(directory.join("dependencies.jsonl")).await.unwrap();
        assert!(dependencies.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()).any(|event| event["event_type"] == "redis_exchange" && event["command"] == "GET"));
        gateway_task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), redis).await.unwrap();
    }).await.unwrap();
}
