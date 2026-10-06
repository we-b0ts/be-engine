use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use traffic_e2e::{AppConfig, AppState, HttpGatewayRuleConfig};

static PORT_BIND_LOCK: Mutex<()> = Mutex::const_new(());

struct Gateway {
    temp: TempDir,
    address: SocketAddr,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    async fn new(upstream: SocketAddr) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut config = AppConfig::default();
        config.http.enabled = false;
        config.mysql.enabled = false;
        config.http_gateway.enabled = true;
        config.http_gateway.listen = address;
        config.http_gateway.matched_upstream = format!("http://{upstream}");
        config.http_gateway.fallback_upstream = format!("http://{upstream}");
        config.http_gateway.rules = vec![HttpGatewayRuleConfig {
            name: Some("sse".to_string()),
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/sse/".to_string()],
            ..Default::default()
        }];
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.case_dependency_post_response_window_ms = 0;
        config.dns_mock.registry_path = temp.path().join("dns.json");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();
        let task = tokio::spawn(async move { state.run().await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while TcpStream::connect(address).await.is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        Self {
            temp,
            address,
            task,
        }
    }

    async fn get(&self, path: &str) -> String {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    fn run_dir(&self) -> PathBuf {
        let entries = directories(&self.temp.path().join("recordings"));
        assert_eq!(entries.len(), 1);
        entries[0].clone()
    }

    fn case(&self, group: &str) -> (Value, Value) {
        let cases = directories(&self.run_dir().join("apis").join(group));
        assert_eq!(cases.len(), 1);
        let read =
            |name| serde_json::from_slice(&std::fs::read(cases[0].join(name)).unwrap()).unwrap();
        (read("request.json"), read("expected-response.json"))
    }
}

fn directories(path: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect()
}

#[tokio::test]
async fn records_open_stream_data_and_releases_the_active_case_for_the_next_request() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buffer = [0; 2048];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: Text/Event-Stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: ready\n\n\r\n").await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let (mut stream, _) = upstream.accept().await.unwrap();
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let gateway = Gateway::new(address).await;
    let response = gateway.get("/sse/events").await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("data: ready\n\n"));
    let (request, expected) = gateway.case("sse-events");
    assert_eq!(
        request["sse_observation"],
        serde_json::json!({"window_ms": 50})
    );
    assert_eq!(
        expected["sse_observation"],
        serde_json::json!({"window_ms": 50, "end": "observation_window_elapsed"})
    );
    assert_eq!(expected["body"]["data"], "data: ready\n\n");
    assert_eq!(expected["body"]["truncated"], false);
    assert!(gateway.get("/sse/next").await.ends_with("ok"));
    let (request, expected) = gateway.case("sse-next");
    assert!(request.get("sse_observation").is_none());
    assert!(expected.get("sse_observation").is_none());
    source.await.unwrap();
}

#[tokio::test]
async fn records_server_eof_with_complete_event_data() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buffer = [0; 2048];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nD\r\ndata: ready\n\n\r\n0\r\n\r\n").await.unwrap();
    });
    let gateway = Gateway::new(address).await;
    assert!(gateway.get("/sse/events").await.contains("data: ready\n\n"));
    let (_, expected) = gateway.case("sse-events");
    assert_eq!(expected["sse_observation"]["end"], "server_eof");
    assert_eq!(expected["body"]["data"], "data: ready\n\n");
    source.await.unwrap();
}

#[tokio::test]
async fn incomplete_http_chunk_does_not_publish_a_successful_sse_case() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buffer = [0; 2048];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\npartial").await.unwrap();
    });
    let gateway = Gateway::new(address).await;
    assert!(gateway.get("/sse/events").await.starts_with("HTTP/1.1 502"));
    assert!(!gateway.run_dir().join("apis/sse-events").exists());
    assert!(gateway.run_dir().join("failed").is_dir());
    source.await.unwrap();
}

#[tokio::test]
async fn unmatched_requests_keep_full_body_forwarding_past_the_sse_window() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buffer = [0; 2048];
        assert!(stream.read(&mut buffer).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream
            .write_all(b"D\r\ndata: ready\n\n\r\n0\r\n\r\n")
            .await
            .unwrap();
    });
    let gateway = Gateway::new(address).await;
    assert!(gateway.get("/fallback").await.contains("data: ready\n\n"));
    assert!(!gateway.run_dir().join("apis/fallback").exists());
    source.await.unwrap();
}
