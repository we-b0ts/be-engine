use super::*;
use tokio::io::AsyncReadExt;

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
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let (client, proxy_client) = tcp_pair().await;
    let (upstream, proxy_upstream) = tcp_pair().await;
    let handler = tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state.clone(),
        KafkaConnectionContext {
            client_addr: None,
            target_host: "kafka.test".into(),
            target_port: 9092,
            target_addr: "kafka.test:9092".into(),
            upstream_addr: "127.0.0.1:9092".into(),
        },
    ));
    (state, temp, client, upstream, handler)
}

async fn send_request(client: &mut TcpStream, upstream: &mut TcpStream, id: i32) {
    let mut payload = BytesMut::new();
    let header = RequestHeader::default()
        .with_request_api_key(ApiKey::Produce as i16)
        .with_request_api_version(8)
        .with_correlation_id(id)
        .with_client_id(Some(StrBytes::from_static_str("termination-test")));
    encode_request_header_into_buffer(&mut payload, &header).unwrap();
    ProduceRequest::default()
        .with_acks(1)
        .with_topic_data(vec![
            TopicProduceData::default()
                .with_name(TopicName(StrBytes::from_static_str("orders")))
                .with_partition_data(vec![
                    PartitionProduceData::default()
                        .with_index(0)
                        .with_records(Some(test_record_batch())),
                ]),
        ])
        .encode(&mut payload, 8)
        .unwrap();
    write_frame(client, &payload).await.unwrap();
    let forwarded = tokio::time::timeout(
        Duration::from_millis(500),
        read_frame(upstream, 1024 * 1024),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(forwarded, payload);
}

async fn events(state: &AppState) -> Vec<serde_json::Value> {
    state.recorder().flush_traffic().await.unwrap();
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    raw.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn residual_response_and_fin_are_forwarded_before_source_timeout() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_request(&mut client, &mut upstream, 7).await;
    let residual = [0, 0, 0, 8, 0, 0];
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
    send_request(&mut client, &mut upstream, 8).await;
    drop(client);
    drop(upstream);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let events = events(&state).await;
    let closed = events
        .iter()
        .find(|event| event["event_type"] == "kafka_connection" && event["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], false);
}

#[tokio::test]
async fn residual_response_reset_is_forwarded_before_source_timeout() {
    let (_state, _temp, mut client, mut upstream, handler) = connected().await;
    send_request(&mut client, &mut upstream, 7).await;
    upstream.write_all(&[0, 0, 0, 8, 0, 0]).await.unwrap();
    sleep(Duration::from_millis(20)).await;
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
async fn request_after_server_fin_is_forwarded_but_not_certified_by_the_old_fin() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_request(&mut client, &mut upstream, 7).await;
    upstream.shutdown().await.unwrap();
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    send_request(&mut client, &mut upstream, 8).await;
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let events = events(&state).await;
    let closed = events
        .iter()
        .find(|event| event["event_type"] == "kafka_connection" && event["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], false);
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "proxy_error"
                && event["error"].as_str().unwrap().contains("post-terminal"))
    );
    let produced: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "kafka_produce")
        .collect();
    assert_eq!(produced.len(), 1);
    assert_eq!(produced[0]["request_sequence"], 1);
}
