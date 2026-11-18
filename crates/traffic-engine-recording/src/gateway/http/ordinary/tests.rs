//! Independent HTTP peers verify delivery separately from case publication.
use serde_json::Value;
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use crate::{
    AppConfig, AppState, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayRuleConfig,
};

fn config(path: &Path, upstream: SocketAddr) -> AppConfig {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut config = AppConfig::default();
    config.http_gateway.enabled = true;
    config.http_gateway.matched_upstream = format!("http://{upstream}");
    config.http_gateway.request_timeout_ms = 3_000;
    config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
    config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
        status: 200,
        body: "busy".into(),
        ..Default::default()
    });
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("ordinary".into()),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/record/".into()],
        ..Default::default()
    }];
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.output_dir = path.join("recordings");
    config.tls.ca_cert_path = path.join("ca.pem");
    config.tls.ca_key_path = path.join("ca-key.pem");
    config
}

async fn gateway(state: AppState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        super::super::run_with_listener(state, listener)
            .await
            .unwrap();
    });
    (address, task)
}

async fn connect(address: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /record/one HTTP/1.1\r\nHost: source.test\r\nTE: trailers\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    client
}

async fn head(client: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    head
}

async fn chunk(client: &mut TcpStream) -> Vec<u8> {
    let mut length = Vec::new();
    while !length.ends_with(b"\r\n") {
        length.push(client.read_u8().await.unwrap());
    }
    let length = usize::from_str_radix(std::str::from_utf8(&length).unwrap().trim(), 16).unwrap();
    let mut bytes = vec![0; length + 2];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes[length..], b"\r\n");
    bytes.truncate(length);
    bytes
}

fn case(root: &Path, category: &str) -> std::path::PathBuf {
    let cases = std::fs::read_dir(root.join(category).join("record-one"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 1);
    cases[0].clone()
}

struct PendingDependency {
    client: TcpStream,
    release: oneshot::Sender<()>,
    source: tokio::task::JoinHandle<()>,
    proxy: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl PendingDependency {
    async fn start(state: AppState) -> Self {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = upstream.local_addr().unwrap();
        let (release, released) = oneshot::channel();
        let (started, request_started) = oneshot::channel();
        let source = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            head(&mut socket).await;
            started.send(()).unwrap();
            released.await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nxy")
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(crate::proxy::http::run_with_listener(state, listener));
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(
                format!("GET http://{authority}/dependency HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        request_started.await.unwrap();
        Self {
            client,
            release,
            source,
            proxy,
        }
    }

    async fn finish(mut self) {
        self.release.send(()).unwrap();
        assert!(head(&mut self.client).await.starts_with(b"HTTP/1.1 200"));
        let mut body = Vec::new();
        self.client.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"xy");
        self.source.await.unwrap();
        self.proxy.abort();
    }
}

#[tokio::test]
async fn ordinary_content_length_delivers_before_eof_and_keeps_tail_case_ownership() {
    incremental(false).await;
}

#[tokio::test]
async fn ordinary_chunked_delivers_frames_and_trailers_before_case_publication() {
    incremental(true).await;
}

async fn incremental(chunked: bool) {
    timeout(Duration::from_secs(5), async {
        let temp = tempfile::tempdir().unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap())).await.unwrap();
        let (release, released) = oneshot::channel();
        let source = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            head(&mut socket).await;
            let first = if chunked { "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n5\r\nfirst\r\n" } else { "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfirst" };
            socket.write_all(first.as_bytes()).await.unwrap();
            released.await.unwrap();
            socket.write_all(if chunked { b"6\r\nsecond\r\n0\r\nX-Checksum: complete\r\n\r\n" } else { b"second" }).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let (address, server) = gateway(state.clone()).await;
        let mut client = connect(address).await;
        let headers = timeout(Duration::from_secs(1), head(&mut client)).await.unwrap();
        assert!(headers.starts_with(b"HTTP/1.1 200"));
        let case_id = state.capture_dependency_targets().cases[0].0.id;
        assert!(String::from_utf8_lossy(&headers).contains(&case_id.to_string()));
        if chunked { assert_eq!(chunk(&mut client).await, b"first"); }
        else { let mut first = [0; 5]; client.read_exact(&mut first).await.unwrap(); assert_eq!(&first, b"first"); }
        assert!(!source.is_finished(), "response delivery must precede Source EOF");
        let dependency = PendingDependency::start(state.clone()).await;
        let mut other = connect(address).await;
        let mut busy = Vec::new();
        other.read_to_end(&mut busy).await.unwrap();
        assert!(busy.ends_with(b"busy"));
        release.send(()).unwrap();
        let mut rest = Vec::new();
        timeout(Duration::from_millis(200), client.read_to_end(&mut rest)).await.expect("response EOF waited for case tail").unwrap();
        if chunked {
            assert!(String::from_utf8_lossy(&rest).to_ascii_lowercase().contains("x-checksum: complete"));
            assert!(rest.windows(6).any(|bytes| bytes == b"second"));
        } else { assert_eq!(rest, b"second"); }
        assert!(state.inner.active_cases.has_case(case_id), "HTTP EOF must retain case admission during tail");
        timeout(Duration::from_secs(1), async {
            while !state.capture_dependency_targets().cases.is_empty() {
                tokio::task::yield_now().await;
            }
        }).await.expect("ordinary response completion must close dependency admission while accepted I/O remains active");
        dependency.finish().await;
        assert!(state.inner.active_cases.wait_for_no_active_case(Duration::from_secs(2)).await);
        source.await.unwrap();
        let expected: Value = serde_json::from_slice(&std::fs::read(case(&state.recorder().run_dir, "apis").join("expected-response.json")).unwrap()).unwrap();
        assert_eq!(expected["body"]["data"], "firstsecond");
        assert!(expected["headers"].get("x-traffic-e2e-case-id").is_none());
        assert!(expected["headers"].get("x-traffic-e2e-finite-response").is_none());
        assert!(expected["duration_ms"].as_u64().unwrap() < 250, "primary response duration must exclude tail wait");
        server.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn ordinary_body_disconnect_preserves_source_and_fails_capture_after_source_eof() {
    timeout(Duration::from_secs(5), async {
        let temp = tempfile::tempdir().unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap()))
            .await
            .unwrap();
        let (finish, finished) = oneshot::channel();
        let source = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            head(&mut socket).await;
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfirst",
                )
                .await
                .unwrap();
            finished.await.unwrap();
            socket
                .write_all(b"second")
                .await
                .expect("downstream cancellation must preserve Source response transport");
        });
        let (address, server) = gateway(state.clone()).await;
        let mut client = connect(address).await;
        head(&mut client).await;
        let mut first = [0; 5];
        client.read_exact(&mut first).await.unwrap();
        crate::dependency::termination::ConnectionControl::new(&client)
            .unwrap()
            .reset()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(state.inner.active_cases.case_slot_occupied());
        finish.send(()).unwrap();
        source.await.unwrap();
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let failed = case(&state.recorder().run_dir, "failed");
        let error: Value =
            serde_json::from_slice(&std::fs::read(failed.join("recording-error.json")).unwrap())
                .unwrap();
        assert_eq!(error["reason"], "downstream_disconnected");
        let expected: Value = serde_json::from_slice(
            &std::fs::read(failed.join("expected-response.json.invalid")).unwrap(),
        )
        .unwrap();
        assert_eq!(expected["body"]["data"], "firstsecond");
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_completed_response_keeps_publication_barrier_for_late_lease_loss() {
    timeout(Duration::from_secs(5), async {
        let temp = tempfile::tempdir().unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap()))
            .await
            .unwrap();
        let (received, received_request) = oneshot::channel();
        let (respond, response_allowed) = oneshot::channel();
        let source = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            head(&mut socket).await;
            received.send(()).unwrap();
            response_allowed.await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let (address, server) = gateway(state.clone()).await;
        let mut client = connect(address).await;
        received_request.await.unwrap();
        let case_id = state.capture_dependency_targets().cases[0].0.id;
        let dependency = PendingDependency::start(state.clone()).await;
        respond.send(()).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"ok"));
        assert!(state.inner.active_cases.has_case(case_id));
        assert!(state.inner.active_cases.invalidate_interaction_reservation(
            Some(case_id),
            crate::recorder::CaseInvalidation::new(
                "interaction_reservation_lost",
                "lease lost during tail"
            )
        ));
        dependency.finish().await;
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let error: Value = serde_json::from_slice(
            &std::fs::read(case(&state.recorder().run_dir, "failed").join("recording-error.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(error["reason"], "interaction_reservation_lost");
        source.await.unwrap();
        server.abort();
    })
    .await
    .unwrap();
}
