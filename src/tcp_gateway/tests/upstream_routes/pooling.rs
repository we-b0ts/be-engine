//! Exercise physical HTTP connections through the routed recording gateway.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

#[tokio::test]
async fn kubernetes_http_uses_a_new_upstream_for_each_large_post() {
    exercise(true, false).await;
}

#[tokio::test]
async fn ordinary_http_keeps_reusing_idle_upstream_connections() {
    exercise(false, false).await;
}

#[tokio::test]
async fn kubernetes_sse_keeps_the_active_connection_until_the_stream_finishes() {
    exercise(true, true).await;
}

async fn exercise(forwarded: bool, streaming: bool) {
    tokio::time::timeout(Duration::from_secs(5), exchanges(forwarded, streaming))
        .await
        .unwrap();
}

async fn exchanges(forwarded: bool, streaming: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let (stop, stopped) = oneshot::channel();
    let accepting = tokio::spawn(serve_upstream(
        upstream,
        connections.clone(),
        requests.clone(),
        streaming,
        stopped,
    ));
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.encrypt_request_headers.clear();
    config.dns_mock.registry_path = temp.path().join("dns.json");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    if forwarded {
        config.dns_mock.enabled = true;
        config.tcp_gateway.enabled = true;
        config.upstream_routes.push(crate::UpstreamRouteConfig {
            host: HOSTNAME.into(),
            via: crate::UpstreamTransportConfig::KubernetesPortForward {
                namespace: "team".into(),
                service: "api".into(),
            },
        });
    }
    let state = crate::AppState::new(config).await.unwrap();
    if forwarded {
        let mut routes = RecordingUpstreams::default();
        routes.insert(HOSTNAME, address.port(), address).unwrap();
        state.install_recording_upstreams(routes).unwrap();
    }
    let fake_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1)), address.port());
    let entry = FakeDnsEntry {
        domain: HOSTNAME.into(),
        fake_ip: Ipv4Addr::new(198, 19, 0, 1),
        real_ips: vec![Ipv4Addr::LOCALHOST],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_address = listener.local_addr().unwrap();
    let serving = state.clone();
    let gateway = tokio::spawn(async move {
        let (client, peer) = listener.accept().await.unwrap();
        serve_http_connection(client, fake_addr, entry, Some(peer.to_string()), serving)
            .await
            .unwrap();
    });
    let socket = TcpStream::connect(gateway_address).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(socket)).await.unwrap();
    let connection = tokio::spawn(connection);
    for index in 0..2 {
        let response = sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/request-{index}"))
                    .header(HOST, format!("{HOSTNAME}:{}", address.port()))
                    .body(Full::new(Bytes::from(vec![b'x'; 86_000])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body.as_ref(),
            if streaming {
                b"data: start\n\ndata: end\n\n".as_slice()
            } else {
                b"ok".as_slice()
            }
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        if forwarded { 2 } else { 1 }
    );
    drop(sender);
    connection.await.unwrap().unwrap();
    gateway.await.unwrap();
    state.recorder().flush_traffic().await.unwrap();
    let traffic =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    let events = traffic
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event_type"] == "http_exchange")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    for event in events {
        assert_eq!(event["authority"], format!("{HOSTNAME}:{}", address.port()));
        assert_eq!(event["response_status"], 200);
        assert_eq!(event["request_body"]["original_len"], 86_000);
    }
    stop.send(()).unwrap();
    accepting.await.unwrap();
}

async fn serve_upstream(
    listener: TcpListener,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    streaming: bool,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            accepted = listener.accept() => {
                let (socket, _) = accepted.unwrap();
                connections.fetch_add(1, Ordering::SeqCst);
                tasks.spawn(upstream_connection(socket, requests.clone(), streaming));
            }
        }
    }
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            assert!(error.is_cancelled(), "{error}");
        }
    }
}

async fn upstream_connection(socket: TcpStream, requests: Arc<AtomicUsize>, streaming: bool) {
    let mut socket = BufReader::new(socket);
    loop {
        let mut line = String::new();
        if socket.read_line(&mut line).await.unwrap() == 0 {
            return;
        }
        assert!(line.starts_with("POST /request-"), "{line}");
        let mut length = 0;
        loop {
            line.clear();
            socket.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        assert_eq!(length, 86_000);
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        assert!(body.iter().all(|byte| *byte == b'x'));
        requests.fetch_add(1, Ordering::SeqCst);
        if streaming {
            socket.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: start\n\n\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            socket
                .get_mut()
                .write_all(b"b\r\ndata: end\n\n\r\n0\r\n\r\n")
                .await
                .unwrap();
        } else {
            socket
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        }
    }
}
