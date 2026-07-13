use std::time::Duration;

use super::*;
use bytes::Bytes;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
        replay_safe: true,
        warnings: Vec::new(),
        started: Instant::now(),
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
            client_process: None,
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
