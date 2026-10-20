use bytes::BytesMut;
use kafka_protocol::messages::produce_request::{PartitionProduceData, TopicProduceData};
use kafka_protocol::messages::produce_response::{PartitionProduceResponse, TopicProduceResponse};
use kafka_protocol::messages::{
    ApiKey, ProduceRequest, ProduceResponse, RequestHeader, ResponseKind, TopicName,
};
use kafka_protocol::protocol::{Encodable, StrBytes, encode_request_header_into_buffer};
use kafka_protocol::records::{
    Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, sleep};

use super::*;
use crate::{AppConfig, AppState};

#[tokio::test]
async fn records_successful_produce_as_semantic_event() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let mut test_client = client_task.await.unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let proxy_upstream = TcpStream::connect(upstream_addr).await.unwrap();
    let (mut broker, _) = upstream_listener.accept().await.unwrap();

    let handler_state = state.clone();
    let handler = tokio::spawn(async move {
        handle_connected(
            proxy_client,
            proxy_upstream,
            handler_state,
            KafkaConnectionContext {
                client_addr: None,
                target_host: "kafka.internal".to_string(),
                target_port: 9092,
                target_addr: "kafka.internal:9092".to_string(),
                upstream_addr: upstream_addr.to_string(),
            },
        )
        .await
    });

    let mut request_payload = BytesMut::new();
    let header = RequestHeader::default()
        .with_request_api_key(ApiKey::Produce as i16)
        .with_request_api_version(8)
        .with_correlation_id(7)
        .with_client_id(Some(StrBytes::from_static_str("recording-test")));
    encode_request_header_into_buffer(&mut request_payload, &header).unwrap();
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
        .encode(&mut request_payload, 8)
        .unwrap();
    write_frame(&mut test_client, &request_payload)
        .await
        .unwrap();

    let request = read_frame(&mut broker, 1024 * 1024).await.unwrap().unwrap();
    assert_eq!(request, request_payload.freeze());
    let response = ResponseKind::Produce(ProduceResponse::default().with_responses(vec![
        TopicProduceResponse::default()
            .with_name(TopicName(StrBytes::from_static_str("orders")))
            .with_partition_responses(vec![PartitionProduceResponse::default()
                .with_index(0)
                .with_error_code(0)]),
    ]));
    sleep(Duration::from_millis(20)).await;
    let response = crate::kafka::encode_response(7, ApiKey::Produce, 8, &response).unwrap();
    write_frame(&mut broker, &response).await.unwrap();
    let _ = read_frame(&mut test_client, 1024 * 1024)
        .await
        .unwrap()
        .unwrap();
    drop(test_client);
    drop(broker);
    handler.await.unwrap().unwrap();
    state.recorder().flush_traffic().await.unwrap();

    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let traffic = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(traffic.contains(r#""event_type":"kafka_produce""#));
    assert!(traffic.contains(r#""topic":"orders""#));
    assert!(traffic.contains(r#""result":"accepted""#));
    assert!(traffic.contains(r#""outcome":"response""#));
    let produce = traffic
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|value| value["event_type"] == "kafka_produce")
        .unwrap();
    assert!(produce["duration_ms"].as_u64().unwrap() >= 20);
}

#[tokio::test]
async fn records_client_terminated_produce_as_replay_safe_timeout() {
    records_terminated_produce(false).await;
}

#[tokio::test]
async fn records_server_terminated_produce_without_waiting_for_client_timeout() {
    records_terminated_produce(true).await;
}

async fn records_terminated_produce(server_ended: bool) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
    let (proxy_client, _) = client_listener.accept().await.unwrap();
    let mut test_client = client_task.await.unwrap();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let proxy_upstream = TcpStream::connect(upstream_addr).await.unwrap();
    let (mut broker, _) = upstream_listener.accept().await.unwrap();

    let handler_state = state.clone();
    let handler = tokio::spawn(async move {
        handle_connected(
            proxy_client,
            proxy_upstream,
            handler_state,
            KafkaConnectionContext {
                client_addr: None,
                target_host: "kafka.internal".to_string(),
                target_port: 9092,
                target_addr: "kafka.internal:9092".to_string(),
                upstream_addr: upstream_addr.to_string(),
            },
        )
        .await
    });

    let mut request_payload = BytesMut::new();
    let header = RequestHeader::default()
        .with_request_api_key(ApiKey::Produce as i16)
        .with_request_api_version(8)
        .with_correlation_id(8)
        .with_client_id(Some(StrBytes::from_static_str("timeout-test")));
    encode_request_header_into_buffer(&mut request_payload, &header).unwrap();
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
        .encode(&mut request_payload, 8)
        .unwrap();
    write_frame(&mut test_client, &request_payload)
        .await
        .unwrap();
    let _ = read_frame(&mut broker, 1024 * 1024).await.unwrap().unwrap();
    sleep(Duration::from_millis(30)).await;
    if server_ended {
        broker.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                read_frame(&mut test_client, 1024 * 1024)
            )
            .await
            .unwrap()
            .unwrap()
            .is_none()
        );
        drop(test_client);
        drop(broker);
    } else {
        drop(test_client);
        sleep(Duration::from_millis(10)).await;
        drop(broker);
    }

    handler.await.unwrap().unwrap();
    state.recorder().flush_traffic().await.unwrap();
    let run_dir = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let traffic = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    let produce = traffic
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|value| value["event_type"] == "kafka_produce")
        .unwrap();
    assert_eq!(
        produce["outcome"]["terminated"]["side"],
        if server_ended { "server" } else { "client" }
    );
    assert_eq!(
        produce["result"],
        if server_ended {
            "server_terminated"
        } else {
            "client_terminated"
        }
    );
    assert_eq!(produce["replay_safe"], true);
    assert!(produce["duration_ms"].as_u64().unwrap() >= 30);
}

fn test_record_batch() -> bytes::Bytes {
    let record = Record {
        transactional: false,
        control: false,
        partition_leader_epoch: 0,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        offset: 0,
        sequence: -1,
        timestamp: 123,
        key: Some(bytes::Bytes::from_static(b"key")),
        value: Some(bytes::Bytes::from_static(b"value")),
        headers: Default::default(),
    };
    let mut encoded = BytesMut::new();
    RecordBatchEncoder::encode(
        &mut encoded,
        [&record],
        &RecordEncodeOptions {
            version: 2,
            compression: Compression::None,
        },
    )
    .unwrap();
    encoded.freeze()
}

mod termination;
