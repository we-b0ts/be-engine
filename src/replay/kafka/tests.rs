use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::{Bytes, BytesMut};
use kafka_protocol::messages::fetch_request::{FetchPartition, FetchTopic};
use kafka_protocol::messages::join_group_request::JoinGroupRequestProtocol;
use kafka_protocol::messages::metadata_request::MetadataRequestTopic;
use kafka_protocol::messages::produce_request::{PartitionProduceData, TopicProduceData};
use kafka_protocol::messages::sync_group_request::SyncGroupRequestAssignment;
use kafka_protocol::messages::{
    ApiKey, ApiVersionsRequest, ApiVersionsResponse, ConsumerProtocolSubscription, FetchRequest,
    FetchResponse, FindCoordinatorRequest, FindCoordinatorResponse, GroupId, HeartbeatRequest,
    HeartbeatResponse, JoinGroupRequest, JoinGroupResponse, MetadataRequest, MetadataResponse,
    ProduceRequest, ProduceResponse, RequestHeader, ResponseHeader, SyncGroupRequest,
    SyncGroupResponse, TopicName,
};
use kafka_protocol::protocol::{
    Decodable, Encodable, HeaderVersion, Request, StrBytes, encode_request_header_into_buffer,
};
use kafka_protocol::records::{
    Compression, Record, RecordBatchDecoder, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::kafka::{read_frame, write_frame};

use super::super::{ReplayConfig, ReplayRuntime};

#[tokio::test]
async fn matches_recorded_produce_and_returns_success() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type": "kafka_produce",
            "connection_id": "00000000-0000-0000-0000-000000000001",
            "request_sequence": 1,
            "target_host": "kafka.internal",
            "target_port": 9092,
            "topic": "orders",
            "key": capture_json(b"key"),
            "headers": [],
            "value": capture_json(b"value"),
            "result": "accepted",
            "outcome": "response",
            "duration_ms": 25,
            "replay_safe": true
        }),
    )
    .await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, report_path.clone()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    let versions: ApiVersionsResponse = send_request(
        &mut client,
        ApiKey::ApiVersions,
        3,
        ApiVersionsRequest::default()
            .with_client_software_name(StrBytes::from_static_str("test"))
            .with_client_software_version(StrBytes::from_static_str("1")),
    )
    .await;
    assert!(versions.api_keys.iter().any(|api| {
        api.api_key == ApiKey::Produce as i16 && api.min_version == 3 && api.max_version == 8
    }));

    let request = ProduceRequest::default().with_acks(1).with_topic_data(vec![
        TopicProduceData::default()
            .with_name(topic("orders"))
            .with_partition_data(vec![
                PartitionProduceData::default()
                    .with_index(0)
                    .with_records(Some(record_batch(b"key", b"value", 123))),
            ]),
    ]);
    let started = tokio::time::Instant::now();
    let response: ProduceResponse = send_request(&mut client, ApiKey::Produce, 8, request).await;
    assert!(started.elapsed() >= std::time::Duration::from_millis(25));
    assert_eq!(response.responses[0].partition_responses[0].error_code, 0);

    let report = wait_for_kafka_matches(&report_path, 1).await;
    assert_eq!(report["kafka"]["matched"].as_array().unwrap().len(), 1);
    assert!(report["kafka"]["unmatched"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn delivers_recorded_fetch_only_once() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type": "kafka_fetch",
            "connection_id": "00000000-0000-0000-0000-000000000002",
            "sequence": 1,
            "target_host": "kafka.internal",
            "target_port": 9092,
            "topics": ["payments"],
            "outcome": "response",
            "duration_ms": 0,
            "replay_safe": true
        }),
    )
    .await;
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type": "kafka_delivery",
            "connection_id": "00000000-0000-0000-0000-000000000002",
            "fetch_sequence": 1,
            "target_host": "kafka.internal",
            "target_port": 9092,
            "topic": "payments",
            "key": capture_json(b"payment-1"),
            "headers": [],
            "value": capture_json(b"paid"),
            "message_timestamp_ms": 456,
            "replay_safe": true
        }),
    )
    .await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, report_path.clone()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = fetch_request("payments");

    let first: FetchResponse = send_request(&mut client, ApiKey::Fetch, 11, request.clone()).await;
    let mut encoded = first.responses[0].partitions[0].records.clone().unwrap();
    let records = RecordBatchDecoder::decode_all(&mut encoded)
        .unwrap()
        .into_iter()
        .flat_map(|batch| batch.records)
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key.as_deref(), Some(b"payment-1".as_slice()));
    assert_eq!(records[0].value.as_deref(), Some(b"paid".as_slice()));

    let second: FetchResponse = send_request(&mut client, ApiKey::Fetch, 11, request).await;
    assert!(second.responses[0].partitions[0].records.is_none());
    let report = wait_for_kafka_matches(&report_path, 2).await;
    assert_eq!(report["kafka"]["matched"][0]["operation"], "fetch");
    assert_eq!(report["kafka"]["matched"][1]["operation"], "delivery");
    task.abort();
}

#[tokio::test]
async fn consumes_recorded_fetch_timeout_when_client_closes_on_schedule() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type": "kafka_fetch",
            "connection_id": "00000000-0000-0000-0000-000000000005",
            "sequence": 1,
            "target_host": "kafka.internal",
            "target_port": 9092,
            "topics": ["payments"],
            "outcome": "client_terminated",
            "duration_ms": 80,
            "replay_safe": true
        }),
    )
    .await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, report_path.clone()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let payload = encode_request(ApiKey::Fetch, 11, fetch_request("payments"));
    let started = tokio::time::Instant::now();
    write_frame(&mut client, &payload).await.unwrap();

    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            read_frame(&mut client, 64 * 1024 * 1024),
        )
        .await
        .is_err()
    );
    tokio::time::sleep_until(started + std::time::Duration::from_millis(80)).await;
    client.shutdown().await.unwrap();

    let report = wait_for_kafka_matches(&report_path, 1).await;
    assert_eq!(report["kafka"]["matched"][0]["operation"], "fetch");
    assert!(
        report["kafka"]["unsafe_events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn server_terminated_fetch_closes_at_the_recorded_time() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type":"kafka_fetch", "connection_id":"00000000-0000-0000-0000-000000000005",
            "sequence":1, "target_host":"kafka.internal", "target_port":9092, "topics":["payments"],
            "outcome":{"terminated":{"side":"server", "kind":"eof", "scope":"write_half"}},
            "duration_ms":50, "replay_safe":true
        }),
    )
    .await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, report_path.clone()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let payload = encode_request(ApiKey::Fetch, 11, fetch_request("payments"));
    let started = tokio::time::Instant::now();
    write_frame(&mut client, &payload).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            read_frame(&mut client, 64 * 1024 * 1024)
        )
        .await
        .unwrap()
        .unwrap()
        .is_none()
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(45));
    let report = wait_for_kafka_matches(&report_path, 1).await;
    assert_eq!(report["kafka"]["matched"][0]["operation"], "fetch");
    drop(client);
    task.abort();
}

#[tokio::test]
async fn wrong_produce_is_unmatched_and_not_accepted() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type": "kafka_produce",
            "connection_id": "00000000-0000-0000-0000-000000000003",
            "request_sequence": 1,
            "target_host": "kafka.internal",
            "target_port": 9092,
            "topic": "orders",
            "key": capture_json(b"key"),
            "headers": [],
            "value": capture_json(b"expected"),
            "result": "accepted",
            "outcome": "response",
            "duration_ms": 0,
            "replay_safe": true
        }),
    )
    .await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, report_path.clone()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = ProduceRequest::default().with_acks(1).with_topic_data(vec![
        TopicProduceData::default()
            .with_name(topic("orders"))
            .with_partition_data(vec![
                PartitionProduceData::default()
                    .with_index(0)
                    .with_records(Some(record_batch(b"key", b"wrong", 123))),
            ]),
    ]);

    let response: ProduceResponse = send_request(&mut client, ApiKey::Produce, 8, request).await;
    assert_ne!(response.responses[0].partition_responses[0].error_code, 0);
    for _ in 0..50 {
        if let Ok(raw) = tokio::fs::read_to_string(&report_path).await {
            let report: Value = serde_json::from_str(&raw).unwrap();
            if report["kafka"]["unmatched"].as_array().unwrap().len() == 1 {
                assert_eq!(report["kafka"]["unused_case"].as_array().unwrap().len(), 1);
                task.abort();
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("Kafka unmatched report was not written");
}

#[tokio::test]
async fn exposes_single_broker_and_single_member_control_plane() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    write_case(
        &case_dir,
        serde_json::json!({
            "event_type": "kafka_delivery",
            "connection_id": "00000000-0000-0000-0000-000000000004",
            "fetch_sequence": 1,
            "target_host": "kafka.internal",
            "target_port": 9092,
            "topic": "payments",
            "key": null,
            "headers": [],
            "value": capture_json(b"paid"),
            "message_timestamp_ms": 456,
            "replay_safe": true
        }),
    )
    .await;
    let report_path = temp.path().join("report.json");
    let (addr, task) = spawn_replay(&case_dir, report_path).await;
    let mut client = TcpStream::connect(addr).await.unwrap();

    let metadata: MetadataResponse = send_request(
        &mut client,
        ApiKey::Metadata,
        8,
        MetadataRequest::default().with_topics(Some(vec![
            MetadataRequestTopic::default().with_name(Some(topic("payments"))),
        ])),
    )
    .await;
    assert_eq!(metadata.brokers.len(), 1);
    assert_eq!(metadata.topics[0].partitions.len(), 1);

    let coordinator: FindCoordinatorResponse = send_request(
        &mut client,
        ApiKey::FindCoordinator,
        2,
        FindCoordinatorRequest::default()
            .with_key(StrBytes::from_static_str("replay-group"))
            .with_key_type(0),
    )
    .await;
    assert_eq!(coordinator.error_code, 0);
    assert_eq!(coordinator.node_id.0, 0);

    let mut subscription = BytesMut::new();
    ConsumerProtocolSubscription::default()
        .with_topics(vec![StrBytes::from_static_str("payments")])
        .encode(&mut subscription, 0)
        .unwrap();
    let joined: JoinGroupResponse = send_request(
        &mut client,
        ApiKey::JoinGroup,
        5,
        JoinGroupRequest::default()
            .with_group_id(GroupId(StrBytes::from_static_str("replay-group")))
            .with_member_id(StrBytes::new())
            .with_protocol_type(StrBytes::from_static_str("consumer"))
            .with_protocols(vec![
                JoinGroupRequestProtocol::default()
                    .with_name(StrBytes::from_static_str("range"))
                    .with_metadata(subscription.freeze()),
            ]),
    )
    .await;
    assert_eq!(joined.error_code, 0);
    assert_eq!(joined.member_id.as_str(), "replay-member");

    let assignment = Bytes::from_static(b"assignment");
    let synced: SyncGroupResponse = send_request(
        &mut client,
        ApiKey::SyncGroup,
        3,
        SyncGroupRequest::default()
            .with_group_id(GroupId(StrBytes::from_static_str("replay-group")))
            .with_generation_id(1)
            .with_member_id(joined.member_id.clone())
            .with_assignments(vec![
                SyncGroupRequestAssignment::default()
                    .with_member_id(joined.member_id.clone())
                    .with_assignment(assignment.clone()),
            ]),
    )
    .await;
    assert_eq!(synced.error_code, 0);
    assert_eq!(synced.assignment, assignment);

    let heartbeat: HeartbeatResponse = send_request(
        &mut client,
        ApiKey::Heartbeat,
        3,
        HeartbeatRequest::default()
            .with_group_id(GroupId(StrBytes::from_static_str("replay-group")))
            .with_generation_id(1)
            .with_member_id(joined.member_id),
    )
    .await;
    assert_eq!(heartbeat.error_code, 0);
    task.abort();
}

async fn send_request<R>(
    stream: &mut TcpStream,
    api_key: ApiKey,
    version: i16,
    request: R,
) -> R::Response
where
    R: Request + Encodable,
    R::Response: Decodable + HeaderVersion,
{
    let payload = encode_request(api_key, version, request);
    write_frame(stream, &payload).await.unwrap();

    let mut response = read_frame(stream, 64 * 1024 * 1024).await.unwrap().unwrap();
    let header =
        ResponseHeader::decode(&mut response, api_key.response_header_version(version)).unwrap();
    assert_eq!(header.correlation_id, 1);
    R::Response::decode(&mut response, version).unwrap()
}

fn encode_request<R>(api_key: ApiKey, version: i16, request: R) -> Bytes
where
    R: Request + Encodable,
{
    let mut payload = BytesMut::new();
    let header = RequestHeader::default()
        .with_request_api_key(api_key as i16)
        .with_request_api_version(version)
        .with_correlation_id(1)
        .with_client_id(Some(StrBytes::from_static_str("test-client")));
    encode_request_header_into_buffer(&mut payload, &header).unwrap();
    request.encode(&mut payload, version).unwrap();
    payload.freeze()
}

fn fetch_request(topic_name: &str) -> FetchRequest {
    FetchRequest::default().with_topics(vec![
        FetchTopic::default()
            .with_topic(topic(topic_name))
            .with_partitions(vec![
                FetchPartition::default()
                    .with_partition(0)
                    .with_fetch_offset(0),
            ]),
    ])
}

fn record_batch(key: &[u8], value: &[u8], timestamp: i64) -> Bytes {
    let record = Record {
        transactional: false,
        control: false,
        partition_leader_epoch: 0,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        offset: 0,
        sequence: -1,
        timestamp,
        key: Some(Bytes::copy_from_slice(key)),
        value: Some(Bytes::copy_from_slice(value)),
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

fn topic(value: &str) -> TopicName {
    TopicName(StrBytes::from_string(value.to_string()))
}

fn capture_json(bytes: &[u8]) -> Value {
    serde_json::json!({
        "encoding": "base64",
        "original_len": bytes.len(),
        "stored_len": bytes.len(),
        "data": STANDARD.encode(bytes),
        "truncated": false
    })
}

async fn write_case(case_dir: &Path, dependency: Value) {
    tokio::fs::create_dir_all(case_dir).await.unwrap();
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(case_dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    file.write_all(serde_json::to_string(&dependency).unwrap().as_bytes())
        .await
        .unwrap();
    file.write_all(b"\n").await.unwrap();
}

async fn spawn_replay(
    case_dir: &Path,
    report_path: PathBuf,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    super::super::write_test_recording_network_manifest(case_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: case_dir.to_path_buf(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".to_string(),
            report_path: Some(report_path),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
            ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        addr,
    )
    .await
    .unwrap();
    runtime.write_report().await.unwrap();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = runtime.run_tcp(listener) => {},
            _ = runtime.run_report_writer() => {},
        }
    });
    (addr, task)
}

async fn wait_for_kafka_matches(path: &Path, expected: usize) -> Value {
    for _ in 0..150 {
        if let Ok(raw) = tokio::fs::read_to_string(path).await
            && let Ok(report) = serde_json::from_str::<Value>(&raw)
            && report["kafka"]["matched"]
                .as_array()
                .is_some_and(|matched| matched.len() == expected)
        {
            return report;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("Kafka replay report did not reach {expected} matches");
}
