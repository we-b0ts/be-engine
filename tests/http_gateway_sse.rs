use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use traffic_e2e::{
    AppConfig, AppState, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayRuleConfig, InteractionPolicy, StreamTerminal,
};

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
    async fn new(upstream: SocketAddr, fixed_fallback: bool) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        initialize_private_key(temp.path());
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut config = AppConfig::default();
        config.http.enabled = false;
        config.mysql.enabled = false;
        config.http_gateway.enabled = true;
        config.http_gateway.record_streaming = true;
        config.http_gateway.listen = address;
        config.http_gateway.matched_upstream = format!("http://{upstream}");
        config.http_gateway.fallback_upstream = format!("http://{upstream}");
        config.http_gateway.interaction = InteractionPolicy {
            business_idle_ms: 80,
            max_duration_ms: 3_000,
            request_timeout_ms: 1_000,
            cleanup_timeout_ms: 1_000,
            input_gap_ms: 1,
            stream_terminal: Some(StreamTerminal::Text {
                value: "[DONE]".into(),
            }),
            ..Default::default()
        };
        if fixed_fallback {
            config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
            config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
                status: 503,
                body: "recording quiesced".into(),
                ..Default::default()
            });
        }
        config.http_gateway.rules = vec![HttpGatewayRuleConfig {
            name: Some("sse".to_string()),
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/sse/".to_string()],
            ..Default::default()
        }];
        config.recording.output_dir = recordings_dir(temp.path());
        config.recording.api_origin_dependency_idle_ms = 30;
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
                format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .unwrap();
        if let Err(error) = result {
            // An invalid upstream body can abort the already-started response.
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ));
        }
        String::from_utf8(response).unwrap()
    }

    fn run_dir(&self) -> PathBuf {
        let entries = directories(&recordings_dir(self.temp.path()));
        assert_eq!(entries.len(), 1);
        entries[0].clone()
    }

    async fn failed_case(&self) -> PathBuf {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut errors = Vec::new();
                find_files(
                    &self.run_dir().join("failed"),
                    "recording-error.json",
                    &mut errors,
                );
                if let [error] = errors.as_slice() {
                    return error.parent().unwrap().to_owned();
                }
                assert!(errors.is_empty(), "expected exactly one failed case");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("invalid interaction must fail within the cleanup budget")
    }

    async fn published_case(&self) -> PathBuf {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let mut responses = Vec::new();
                find_files(
                    &self.run_dir().join("apis"),
                    "expected-response.json",
                    &mut responses,
                );
                if let [response] = responses.as_slice() {
                    return response.parent().unwrap().to_owned();
                }
                assert!(responses.is_empty(), "expected exactly one published case");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("completed interaction must publish without stopping Source")
    }

    fn assert_no_published_cases(&self) {
        let mut cases = Vec::new();
        find_files(&self.run_dir().join("apis"), "request.json", &mut cases);
        assert!(
            cases.is_empty(),
            "invalid interaction must not publish a case"
        );
    }
}

fn recordings_dir(root: &Path) -> PathBuf {
    root.join(".traffic-e2e/local/artifacts/recordings")
}

fn initialize_private_key(root: &Path) {
    let secrets = root.join(".traffic-e2e/local/secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = std::env::var("TRAFFIC_E2E_ENCRYPTION_KEY_B64").unwrap_or_else(|_| {
        let mut key = [0; 32];
        getrandom::fill(&mut key).unwrap();
        STANDARD.encode(key)
    });
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(secrets.join("traffic-e2e-enc.sec"))
        .unwrap();
    std::io::Write::write_all(&mut file, key.as_bytes()).unwrap();
}

fn find_files(directory: &Path, name: &str, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            find_files(&path, name, files);
        } else if path.file_name().is_some_and(|file| file == name) {
            files.push(path);
        }
    }
}

async fn read_request_head(stream: &mut TcpStream) {
    let mut header = Vec::new();
    while !header.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let count = stream.read(&mut buffer).await.unwrap();
        assert!(count > 0 && header.len() + count <= 8192);
        header.extend_from_slice(&buffer[..count]);
    }
}

fn expected_response(directory: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(directory.join("expected-response.json")).unwrap())
        .unwrap()
}

fn directories(path: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect()
}

#[tokio::test]
async fn closes_completed_stream_promptly_and_publishes_while_source_stays_alive() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let (release_source, released) = oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: Text/Event-Stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: ready\n\n\r\nE\r\ndata: [DONE]\n\n\r\n").await.unwrap();
        let mut buffer = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        released.await.unwrap();
    });
    let gateway = Gateway::new(address, true).await;
    let response = tokio::time::timeout(Duration::from_millis(750), gateway.get("/sse/events"))
        .await
        .expect("the client response must finish before the Source cleanup timeout");
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("data: ready\n\n"));
    assert!(response.contains("data: [DONE]\n\n"));
    let published = gateway.published_case().await;
    let expected = expected_response(&published);
    assert!(expected.get("sse_observation").is_none());
    assert_eq!(expected["interaction"]["protocol"], "sse");
    assert_eq!(expected["interaction"]["end"]["reason"], "business_idle");
    assert_eq!(expected["interaction"]["end"]["clean"], true);
    assert!(
        !source.is_finished(),
        "case completion must preserve Source"
    );
    release_source.send(()).unwrap();
    source.await.unwrap();
}

#[tokio::test]
async fn forwards_complete_server_eof_and_publishes_without_source_process_proof() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nD\r\ndata: ready\n\n\r\n0\r\n\r\n").await.unwrap();
    });
    let gateway = Gateway::new(address, true).await;
    let response = gateway.get("/sse/events").await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("data: ready\n\n"));
    assert!(response.ends_with("0\r\n\r\n"));
    let expected = expected_response(&gateway.published_case().await);
    assert_eq!(expected["interaction"]["end"]["reason"], "server_eof");
    assert_eq!(expected["interaction"]["end"]["clean"], true);
    source.await.unwrap();
}

#[tokio::test]
async fn incomplete_http_chunk_does_not_publish_a_successful_sse_case() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"D\r\npartial").await.unwrap();
    });
    let gateway = Gateway::new(address, true).await;
    let response = gateway.get("/sse/events").await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(!response.ends_with("0\r\n\r\n"));
    gateway.failed_case().await;
    gateway.assert_no_published_cases();
    source.await.unwrap();
}

#[tokio::test]
async fn unmatched_requests_forward_the_complete_stream_body() {
    let _lock = PORT_BIND_LOCK.lock().await;
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream
            .write_all(b"D\r\ndata: ready\n\n\r\n0\r\n\r\n")
            .await
            .unwrap();
    });
    let gateway = Gateway::new(address, false).await;
    let response = gateway.get("/fallback").await;
    assert!(response.contains("data: ready\n\n"));
    assert!(response.ends_with("0\r\n\r\n"));
    gateway.assert_no_published_cases();
    source.await.unwrap();
}
