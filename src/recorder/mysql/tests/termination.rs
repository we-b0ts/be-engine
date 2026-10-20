use super::*;

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap());
    let (client, server) = tokio::join!(client, listener.accept());
    (client.unwrap(), server.unwrap().0)
}

async fn connected() -> (
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
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = tokio::spawn(handle_connected_mysql(
        proxy_client,
        proxy_upstream,
        state.clone(),
        MysqlConnectionContext {
            route_name: None,
            listen_addr: "127.0.0.1:3306".into(),
            client_addr: None,
            target_host: Some("mysql.test".into()),
            target_port: Some(3306),
            target_addr: Some("mysql.test:3306".into()),
            upstream_addr: "127.0.0.1:3306".into(),
        },
    ));
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: server_handshake_payload(0),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    read_packet(&mut client).await.unwrap().unwrap();
    client
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: login_payload("appdb"),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    read_packet(&mut upstream).await.unwrap().unwrap();
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 2,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    read_packet(&mut client).await.unwrap().unwrap();
    (state, temp, client, upstream, handler)
}

async fn recorded_exchange(state: &AppState) -> serde_json::Value {
    state.recorder().flush_traffic().await.unwrap();
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    raw.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|event| event["event_type"] == "mysql_exchange")
        .unwrap()
}

async fn send_query(client: &mut TcpStream, upstream: &mut TcpStream) {
    client
        .write_all(
            &MysqlPacket {
                sequence_id: 0,
                payload: [vec![0x03], b"SELECT value".to_vec()].concat(),
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    read_packet(upstream).await.unwrap().unwrap();
}

#[tokio::test]
async fn server_eof_retains_the_delivered_packet_prefix_and_timing() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_query(&mut client, &mut upstream).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let prefix = MysqlPacket {
        sequence_id: 1,
        payload: vec![0x01],
    }
    .to_wire_bytes();
    upstream.write_all(&prefix).await.unwrap();
    let delivered = read_packet(&mut client).await.unwrap().unwrap();
    assert_eq!(delivered.to_wire_bytes(), prefix);
    tokio::time::sleep(Duration::from_millis(20)).await;
    upstream.shutdown().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), read_packet(&mut client))
            .await
            .unwrap()
            .unwrap()
            .is_none()
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
    assert_eq!(exchange["response"]["status"], "server_terminated");
    assert!(exchange["parse_warnings"].as_array().unwrap().is_empty());
    let packets = exchange["response"]["wire_prefix"].as_array().unwrap();
    assert_eq!(packets.len(), 1);
    assert!(packets[0]["offset_ms"].as_u64().unwrap() >= 15);
    assert!(packets[0]["offset_ms"].as_u64().unwrap() < exchange["duration_ms"].as_u64().unwrap());
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(packets[0]["packet"]["data"].as_str().unwrap())
            .unwrap(),
        prefix
    );
}

#[tokio::test]
async fn client_write_half_close_does_not_discard_a_later_mysql_response() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_query(&mut client, &mut upstream).await;
    client.shutdown().await.unwrap();
    assert!(read_packet(&mut upstream).await.unwrap().is_none());
    upstream
        .write_all(
            &MysqlPacket {
                sequence_id: 1,
                payload: vec![0x00],
            }
            .to_wire_bytes(),
        )
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_millis(200), read_packet(&mut client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.payload, [0x00]);
    drop(upstream);
    drop(client);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let exchange = recorded_exchange(&state).await;
    assert_eq!(exchange["outcome"], "response");
}

#[tokio::test]
async fn residual_response_bytes_and_fin_are_forwarded_before_source_timeout() {
    use tokio::io::AsyncReadExt;
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_query(&mut client, &mut upstream).await;
    // Header promises three bytes, but upstream ends after one payload byte.
    let residual = [3, 0, 0, 1, 0];
    upstream.write_all(&residual).await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut delivered = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(500),
        client.read_to_end(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered, residual);
    drop(client);
    drop(upstream);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let exchange = recorded_exchange(&state).await;
    assert!(!exchange["parse_warnings"].as_array().unwrap().is_empty());
    assert_ne!(exchange["response"]["status"], "ok");
}

#[tokio::test]
async fn residual_response_reset_is_forwarded_before_source_timeout() {
    use crate::dependency::termination::ConnectionControl;
    use tokio::io::AsyncReadExt;
    let (_state, _temp, mut client, mut upstream, handler) = connected().await;
    send_query(&mut client, &mut upstream).await;
    upstream.write_all(&[3, 0, 0, 1, 0]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    ConnectionControl::new(&upstream).unwrap().reset().unwrap();
    let mut delivered = Vec::new();
    let error = tokio::time::timeout(
        Duration::from_millis(500),
        client.read_to_end(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    drop(client);
    drop(upstream);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn request_after_server_fin_is_forwarded_but_cannot_inherit_that_termination() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_query(&mut client, &mut upstream).await;
    upstream.shutdown().await.unwrap();
    assert!(read_packet(&mut client).await.unwrap().is_none());
    // A FIN closes only upstream's write direction. Preserve the reverse path.
    send_query(&mut client, &mut upstream).await;
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
        .filter(|event| event["event_type"] == "mysql_exchange")
        .collect();
    assert_eq!(exchanges.len(), 2);
    let later = &exchanges[1];
    assert!(later["outcome"].get("terminated").is_none());
    assert!(
        later["parse_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("post-terminal"))
    );
}
