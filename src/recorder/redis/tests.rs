use std::os::fd::AsRawFd;
use std::time::Duration;

use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{AppConfig, RecordingAccessPolicy};

use super::*;

#[test]
fn authentication_secrets_are_never_recorded() {
    let auth = RedisCommand {
        name: "AUTH".to_string(),
        args: vec![b"alice".to_vec(), b"super-secret".to_vec()],
    };
    let (args, session_setup, replay_safe, _) = sanitize_and_classify(&auth);
    assert_eq!(args, vec![b"alice".to_vec(), b"<redacted>".to_vec()]);
    assert!(session_setup);
    assert!(replay_safe);

    let hello = RedisCommand {
        name: "HELLO".to_string(),
        args: vec![
            b"3".to_vec(),
            b"AUTH".to_vec(),
            b"alice".to_vec(),
            b"another-secret".to_vec(),
        ],
    };
    let (args, _, _, _) = sanitize_and_classify(&hello);
    assert_eq!(args[2], b"alice");
    assert_eq!(args[3], b"<redacted>");
}

#[tokio::test]
async fn blocked_write_returns_ordered_error_without_reaching_upstream() {
    let (state, _temp) = test_state(RecordingAccessPolicy::BlockKnownWrites).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    client
        .write_all(b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n")
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&response[..read]).starts_with("-READONLY"));

    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.read(&mut probe))
            .await
            .is_err()
    );
    handler.abort();
}

#[tokio::test]
async fn completed_exchange_accepts_abortive_client_close() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    let response = b"$5\r\nvalue\r\n";
    upstream.write_all(response).await.unwrap();
    let mut received_response = vec![0_u8; response.len()];
    client.read_exact(&mut received_response).await.unwrap();
    assert_eq!(received_response, response);

    enable_abortive_close(&client);
    drop(client);

    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);

    let result = tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn pending_exchange_records_client_termination_as_replay_safe() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
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
        .find(|value| value["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["outcome"], "client_terminated");
    assert_eq!(exchange["response"]["original_len"], 0);
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 50);
}

#[tokio::test]
async fn pending_quit_is_a_safe_debug_only_terminal_exchange() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*1\r\n$4\r\nQUIT\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    drop(upstream);
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.shutdown().await.unwrap();
    drop(client);

    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let events = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    let exchange = events
        .iter()
        .find(|value| value["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["command"], "QUIT");
    assert_eq!(exchange["outcome"], "no_response");
    assert_eq!(exchange["replay_safe"], true);
    assert_eq!(exchange["parse_warnings"], serde_json::json!([]));
    let closed = events
        .iter()
        .find(|value| value["event_type"] == "redis_connection" && value["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], true);

    state
        .recorder()
        .flush_bootstrap_dependency_files()
        .await
        .unwrap();
    let semantic = tokio::fs::read_to_string(
        state
            .recorder()
            .run_dir
            .join("bootstrap-dependencies.jsonl"),
    )
    .await
    .unwrap();
    assert!(!semantic.contains("\"command\":\"QUIT\""));
    let debug = tokio::fs::read_to_string(
        state
            .recorder()
            .run_dir
            .join("bootstrap-dependencies-debug.jsonl"),
    )
    .await
    .unwrap();
    assert!(debug.contains("\"command\":\"QUIT\""));
}

#[tokio::test]
async fn partial_request_rejects_abortive_client_close() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nke")
        .await
        .unwrap();
    enable_abortive_close(&client);
    drop(client);

    let mut forwarded = Vec::new();
    upstream.read_to_end(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, b"*2\r\n$3\r\nGET\r\n$3\r\nke");
    drop(upstream);

    let result = tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
}

async fn test_state(access_policy: RecordingAccessPolicy) -> (AppState, TempDir) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = access_policy;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    (AppState::new(config).await.unwrap(), temp)
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(addr));
    let (server, _) = listener.accept().await.unwrap();
    (client.await.unwrap().unwrap(), server)
}

fn spawn_handler(
    proxy_client: TcpStream,
    proxy_upstream: TcpStream,
    state: AppState,
    upstream_addr: std::net::SocketAddr,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state,
        ConnectionContext {
            client_addr: None,
            target_host: "redis.test".to_string(),
            target_port: 6379,
            target_addr: "redis.test:6379".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
    ))
}

fn enable_abortive_close(stream: &TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "failed to enable abortive close");
}
