use super::*;

async fn connected(
    wire: MemcachedWireProtocol,
) -> (
    AppState,
    tempfile::TempDir,
    TcpStream,
    TcpStream,
    tokio::task::JoinHandle<Result<()>>,
) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let (client, proxy_client) = memcached_tcp_pair().await;
    let (upstream, proxy_upstream) = memcached_tcp_pair().await;
    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state.clone(),
        ConnectionContext {
            client_addr: None,
            target_host: "cache.test".into(),
            target_port: 11211,
            target_addr: "cache.test:11211".into(),
            upstream_addr: "127.0.0.1:11211".into(),
        },
        wire,
    ));
    (state, temp, client, upstream, handler)
}

async fn recorded_exchange(state: &AppState) -> serde_json::Value {
    state.recorder().flush_traffic().await.unwrap();
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    raw.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["event_type"] == "memcached_exchange")
        .unwrap()
}

#[tokio::test]
async fn server_eof_is_transparent_and_keeps_the_observation_clock() {
    let (state, _temp, mut client, mut upstream, handler) =
        connected(MemcachedWireProtocol::Text).await;
    client.write_all(b"get key\r\n").await.unwrap();
    let mut request = [0; 9];
    upstream.read_exact(&mut request).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    upstream.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), client.read(&mut probe))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let exchange = recorded_exchange(&state).await;
    assert_eq!(exchange["outcome"]["terminated"]["side"], "server");
    assert_eq!(exchange["outcome"]["terminated"]["kind"], "eof");
    assert_eq!(exchange["replay_safe"], true);
    let elapsed = exchange["duration_ms"].as_u64().unwrap();
    assert!(
        (20..100).contains(&elapsed),
        "cleanup must not extend the recorded duration: {elapsed}"
    );
}

#[tokio::test]
async fn client_write_half_close_still_receives_a_complete_response() {
    let (state, _temp, mut client, mut upstream, handler) =
        connected(MemcachedWireProtocol::Text).await;
    client.write_all(b"get key\r\n").await.unwrap();
    let mut request = [0; 9];
    upstream.read_exact(&mut request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(upstream.read(&mut probe).await.unwrap(), 0);
    upstream.write_all(b"END\r\n").await.unwrap();
    let mut response = [0; 5];
    tokio::time::timeout(Duration::from_millis(200), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"END\r\n");
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(recorded_exchange(&state).await["outcome"], "response");
}

#[tokio::test]
async fn server_reset_is_forwarded_as_reset_and_recorded() {
    let (state, _temp, mut client, mut upstream, handler) =
        connected(MemcachedWireProtocol::Text).await;
    client.write_all(b"get key\r\n").await.unwrap();
    let mut request = [0; 9];
    upstream.read_exact(&mut request).await.unwrap();
    ConnectionControl::new(&upstream).unwrap().reset().unwrap();
    let mut probe = [0];
    let error = tokio::time::timeout(Duration::from_millis(200), client.read(&mut probe))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let exchange = recorded_exchange(&state).await;
    assert_eq!(exchange["outcome"]["terminated"]["side"], "server");
    assert_eq!(exchange["outcome"]["terminated"]["kind"], "reset");
    assert_eq!(exchange["replay_safe"], true);
}

#[tokio::test]
async fn binary_stats_prefix_survives_server_termination() {
    let (state, _temp, mut client, mut upstream, handler) =
        connected(MemcachedWireProtocol::Binary).await;
    let mut request = vec![0; 24];
    request[0] = 0x80;
    request[1] = 0x10;
    request[12..16].copy_from_slice(&42_u32.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut forwarded = [0; 24];
    upstream.read_exact(&mut forwarded).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut prefix = vec![0; 24];
    prefix[0] = 0x81;
    prefix[1] = 0x10;
    prefix[2..4].copy_from_slice(&3_u16.to_be_bytes());
    prefix[8..12].copy_from_slice(&4_u32.to_be_bytes());
    prefix[12..16].copy_from_slice(&42_u32.to_be_bytes());
    prefix.extend_from_slice(b"key1");
    upstream.write_all(&prefix).await.unwrap();
    let mut delivered = vec![0; prefix.len()];
    client.read_exact(&mut delivered).await.unwrap();
    assert_eq!(delivered, prefix);
    tokio::time::sleep(Duration::from_millis(20)).await;
    upstream.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), client.read(&mut probe))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let exchange = recorded_exchange(&state).await;
    assert_eq!(exchange["outcome"]["terminated"]["side"], "server");
    assert_eq!(exchange["replay_safe"], true);
    assert_eq!(exchange["response_frames"].as_array().unwrap().len(), 1);
    let offsets = exchange["response_frame_offsets_ms"].as_array().unwrap();
    assert_eq!(offsets.len(), 1);
    assert!(offsets[0].as_u64().unwrap() >= 15);
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(exchange["response_frames"][0]["data"].as_str().unwrap())
            .unwrap(),
        prefix
    );
}

#[tokio::test]
async fn request_after_server_fin_is_forwarded_but_not_certified_by_the_old_fin() {
    let (state, _temp, mut client, mut upstream, handler) =
        connected(MemcachedWireProtocol::Text).await;
    client.write_all(b"get key\r\n").await.unwrap();
    upstream.read_exact(&mut [0; 9]).await.unwrap();
    upstream.shutdown().await.unwrap();
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    client.write_all(b"get key\r\n").await.unwrap();
    tokio::time::timeout(Duration::from_millis(500), upstream.read_exact(&mut [0; 9]))
        .await
        .unwrap()
        .unwrap();
    drop(client);
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
    let exchanges: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event_type"] == "memcached_exchange")
        .collect();
    assert_eq!(exchanges.len(), 2);
    let later = &exchanges[1];
    assert_eq!(later["replay_safe"], false);
    assert!(later["outcome"].get("terminated").is_none());
    assert!(
        later["parse_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("post-terminal"))
    );
}
