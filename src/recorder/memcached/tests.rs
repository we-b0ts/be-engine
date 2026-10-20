use std::time::Duration;

use super::*;
use bytes::Bytes;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::recorder::CaseContext;
use crate::{AppConfig, RecordingAccessPolicy};

#[tokio::test]
async fn noop_response_confirms_preceding_quiet_success() {
    let pending = Arc::new(Mutex::new(VecDeque::from([
        pending_binary_request(1, 0x09, true),
        pending_binary_request(2, 0x0a, false),
    ])));
    let frame = BinaryFrame {
        raw: Bytes::from(vec![0x81; 24]),
        magic: 0x81,
        opcode: 0x0a,
        opaque: 2,
        cas: 0,
        extras: Vec::new(),
        key: Vec::new(),
        value: Vec::new(),
    };

    let (quiet, completed) = correlate_binary_response(&pending, &frame).await.unwrap();
    assert_eq!(quiet.len(), 1);
    assert_eq!(quiet[0].request.opaque, Some(1));
    assert_eq!(completed.unwrap().request.opaque, Some(2));
    assert!(pending.lock().await.is_empty());
}

fn pending_binary_request(opaque: u32, opcode: u8, quiet: bool) -> PendingMemcachedExchange {
    PendingMemcachedExchange {
        sequence: opaque as u64,
        request: MemcachedRequest {
            raw: Bytes::new(),
            command: "get".to_string(),
            opcode: Some(opcode),
            opaque: Some(opaque),
            key: Some(b"key".to_vec()),
            args: Vec::new(),
            value: None,
            extras: None,
            cas: None,
            noreply: false,
            quiet,
        },
        response_frames: Vec::new(),
        response_frame_offsets_ms: Vec::new(),
        replay_safe: true,
        warnings: Vec::new(),
        started: Instant::now(),
        termination: None,
    }
}

#[tokio::test]
async fn blocked_text_write_does_not_reach_upstream() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(client_addr));
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let mut client = client.await.unwrap().unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let proxy_upstream = tokio::spawn(TcpStream::connect(upstream_addr));
    let (mut upstream, _) = upstream_listener.accept().await.unwrap();
    let proxy_upstream = proxy_upstream.await.unwrap().unwrap();

    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state,
        ConnectionContext {
            client_addr: None,
            target_host: "cache.test".to_string(),
            target_port: 11211,
            target_addr: "cache.test:11211".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
        MemcachedWireProtocol::Text,
    ));

    client
        .write_all(b"set key 0 60 5\r\nvalue\r\n")
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&response[..read]).starts_with("CLIENT_ERROR"));

    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.read(&mut probe))
            .await
            .is_err()
    );
    handler.abort();
}

#[tokio::test]
async fn pending_text_exchange_records_client_termination_as_replay_safe() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(client_addr));
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let mut client = client.await.unwrap().unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let proxy_upstream = tokio::spawn(TcpStream::connect(upstream_addr));
    let (mut upstream, _) = upstream_listener.accept().await.unwrap();
    let proxy_upstream = proxy_upstream.await.unwrap().unwrap();

    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state.clone(),
        ConnectionContext {
            client_addr: None,
            target_host: "cache.test".to_string(),
            target_port: 11211,
            target_addr: "cache.test:11211".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
        MemcachedWireProtocol::Text,
    ));

    let request = b"get key\r\n";
    client.write_all(request).await.unwrap();
    let mut forwarded = vec![0_u8; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    client.shutdown().await.unwrap();
    drop(client);
    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let exchange = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["event_type"] == "memcached_exchange")
        .unwrap();
    assert_eq!(exchange["outcome"]["terminated"]["side"], "client");
    assert_eq!(exchange["response_frames"].as_array().unwrap().len(), 0);
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 50);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_request_is_pending_before_upstream_write_completes() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.max_body_bytes = 16 * 1024 * 1024;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(client_addr));
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let mut client = client.await.unwrap().unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let proxy_upstream = tokio::spawn(TcpStream::connect(upstream_addr));
    let (mut upstream, _) = upstream_listener.accept().await.unwrap();
    let proxy_upstream = proxy_upstream.await.unwrap().unwrap();
    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state.clone(),
        ConnectionContext {
            client_addr: None,
            target_host: "cache.test".to_string(),
            target_port: 11211,
            target_addr: "cache.test:11211".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
        MemcachedWireProtocol::Text,
    ));

    let value_len = 8 * 1024 * 1024;
    let mut request = format!("set key 0 60 {value_len}\r\n").into_bytes();
    request.resize(request.len() + value_len, b'x');
    request.extend_from_slice(b"\r\n");
    let expected_request_len = request.len();
    let client_io = tokio::spawn(async move {
        client.write_all(&request).await.unwrap();
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"STORED\r\n");
        client.shutdown().await.unwrap();
    });

    let mut first_byte = [0_u8; 1];
    upstream.read_exact(&mut first_byte).await.unwrap();
    upstream.write_all(b"STORED\r\n").await.unwrap();
    let mut forwarded = Vec::new();
    upstream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(forwarded.len() + 1, expected_request_len);
    drop(upstream);

    tokio::time::timeout(Duration::from_secs(5), client_io)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(!traffic.contains("response has no pending request"));
}

#[tokio::test]
async fn text_connection_preserves_sequential_exchanges_across_an_idle_gap() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let (mut client, proxy_client) = memcached_tcp_pair().await;
    let (mut upstream, proxy_upstream) = memcached_tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state.clone(),
        ConnectionContext {
            client_addr: None,
            target_host: "cache.test".to_string(),
            target_port: 11211,
            target_addr: "cache.test:11211".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
        MemcachedWireProtocol::Text,
    ));

    for (index, request) in [b"get first\r\n".as_slice(), b"get second\r\n".as_slice()]
        .into_iter()
        .enumerate()
    {
        client.write_all(request).await.unwrap();
        let mut forwarded = vec![0_u8; request.len()];
        upstream.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, request);
        upstream.write_all(b"END\r\n").await.unwrap();
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"END\r\n");

        if index == 0 {
            // Let the server-to-client task finish recording the first
            // exchange and wait for more upstream bytes while the pending
            // queue is empty. The next response must be correlated with the
            // request that arrives during that wait.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    client.shutdown().await.unwrap();
    upstream.shutdown().await.unwrap();
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let events = traffic
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event_type"] == "memcached_exchange")
            .count(),
        2
    );
    assert!(
        events
            .iter()
            .all(|event| event["event_type"] != "proxy_error")
    );
}

#[tokio::test]
async fn raw_fallback_reports_later_case_activity_on_the_same_connection() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let first_case = memcached_test_case("first");
    let first_guard = state.try_reserve_active_case(first_case.clone()).unwrap();
    state
        .activate_case_dependencies(&first_guard)
        .expect("first case dependencies should activate");

    let (mut client, proxy_client) = memcached_tcp_pair().await;
    let (mut upstream, proxy_upstream) = memcached_tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state.clone(),
        ConnectionContext {
            client_addr: None,
            target_host: "cache.test".to_string(),
            target_port: 11211,
            target_addr: "cache.test:11211".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
        MemcachedWireProtocol::Text,
    ));

    upstream.write_all(b"END\r\n").await.unwrap();
    let mut unsolicited = [0_u8; 5];
    client.read_exact(&mut unsolicited).await.unwrap();
    assert_eq!(&unsolicited, b"END\r\n");
    drop(first_guard);

    let second_case = memcached_test_case("second");
    let second_guard = state.try_reserve_active_case(second_case.clone()).unwrap();
    state
        .activate_case_dependencies(&second_guard)
        .expect("second case dependencies should activate");
    let request = b"get key\r\n";
    client.write_all(request).await.unwrap();
    let mut forwarded = vec![0_u8; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, request);

    client.shutdown().await.unwrap();
    upstream.shutdown().await.unwrap();
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let first_errors = memcached_case_proxy_errors(&state, &first_case).await;
    let second_errors = memcached_case_proxy_errors(&state, &second_case).await;
    assert_eq!(first_errors.len(), 1);
    assert_eq!(second_errors.len(), 1);
    assert_eq!(
        first_errors[0]["connection_id"],
        second_errors[0]["connection_id"]
    );
    assert_eq!(second_errors[0]["protocol"], "memcached");
    assert_eq!(
        second_errors[0]["error"],
        "Memcached text response has no pending request; switched to raw forwarding"
    );
}

fn memcached_test_case(name: &str) -> CaseContext {
    CaseContext {
        id: Uuid::new_v4(),
        rule_name: name.to_string(),
        uri_group: None,
    }
}

async fn memcached_case_proxy_errors(
    state: &AppState,
    case: &CaseContext,
) -> Vec<serde_json::Value> {
    let dir = state.recorder().case_staging_dir(case);
    state
        .recorder()
        .flush_case_dependency_files(&dir)
        .await
        .unwrap();
    let raw = tokio::fs::read_to_string(dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    raw.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event_type"] == "proxy_error")
        .collect()
}

async fn memcached_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(addr));
    let (server, _) = listener.accept().await.unwrap();
    (client.await.unwrap().unwrap(), server)
}

mod termination;
