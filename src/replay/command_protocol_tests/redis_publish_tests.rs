//! PUBLISH shares the global JSON formats and complete identity correspondence.
use super::*;
use redis_value_tests::spawn;

const SOURCE_A: &str = "0123456789ab4def8123456789abcdef";
const SOURCE_B: &str = "1123456789ab4def8123456789abcdef";
const TARGET_A: &str = "fedcba98765443218123456789abcdef";
const TARGET_B: &str = "eedcba98765443218123456789abcdef";
const ERROR: &[u8] = b"-ERR no recorded Redis dependency matched\r\n";

fn payload(id: &str, stage: u8) -> Vec<u8> {
    serde_json::json!({"host_id":id,"stage":stage})
        .to_string()
        .into_bytes()
}

async fn publish(client: &mut TcpStream, channel: &str, payload: &[u8], expected: &[u8]) {
    let mut bytes = b"*3\r\n$7\r\nPUBLISH\r\n".to_vec();
    for argument in [channel.as_bytes(), payload] {
        bytes.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        bytes.extend_from_slice(argument);
        bytes.extend_from_slice(b"\r\n");
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        client.write_all(&bytes).await.unwrap();
        let mut response = vec![0; expected.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected);
    })
    .await
    .expect("PUBLISH request timed out");
}

fn record(connection: Uuid, sequence: u64, id: &str, stage: u8) -> Value {
    let mut record = redis_hash_dependency(
        connection,
        sequence,
        "PUBLISH",
        &["events", "placeholder"],
        format!(":{sequence}\r\n").as_bytes(),
    );
    record["args"][1] = serde_json::json!({"encoding":"base64","truncated":false,"data":STANDARD.encode(payload(id,stage))});
    record["response_kind"] = "integer".into();
    record
}

async fn http_request(address: SocketAddr, id: &str) -> hyper::StatusCode {
    use http_body_util::{BodyExt, Full};
    let client = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            hyper::Request::builder()
                .method("POST")
                .uri("/reference")
                .header("host", "http.test")
                .body(Full::new(bytes::Bytes::from(payload(id, 7))))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    response.into_body().collect().await.unwrap();
    status
}

#[tokio::test]
async fn global_publish_formats_preserve_order_stable_fields_and_cross_protocol_identities() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("apis/publish/case");
    std::fs::create_dir_all(&case).unwrap();
    let connection = Uuid::new_v4();
    let mut records = vec![
        record(connection, 1, SOURCE_A, 1),
        record(connection, 2, SOURCE_A, 2),
        record(connection, 3, SOURCE_B, 3),
    ];
    records.push(serde_json::json!({"event_type":"http_exchange","id":Uuid::new_v4(),
        "scheme":"http","method":"POST","uri":"/reference","authority":"http.test",
        "request_body":{"encoding":"utf8","truncated":false,"data":String::from_utf8(payload(SOURCE_A,7)).unwrap()},
        "response_status":200,"response_headers":{},"response_body":{"encoding":"utf8","truncated":false,"data":"ok"},"error":null}));
    let dependencies = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(case.join("dependencies.jsonl"), &dependencies).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/publish"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(&policy,"format: traffic-policy/v3\njson:\n  fields:\n    /host_id: {kind: identity, formats: [{hex: 32}]}\n").unwrap();
    let (_, state, task) = spawn(&case, Some(policy)).await;
    task.abort();
    // Each physical adapter receives the recorded endpoint selected by the
    // production gateway; loopback alone cannot identify two remote targets.
    let (address, http_address, redis_task, http_task) =
        protocol_listeners(&case, state.clone()).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    // Failed previews retain the original ordered slot and do not pin an ID.
    publish(&mut client, "events", &payload(TARGET_B, 2), ERROR).await;
    publish(&mut client, "other", &payload(TARGET_B, 1), ERROR).await;
    publish(&mut client, "events", &payload("not-hex", 1), ERROR).await;
    publish(&mut client, "events", &payload(TARGET_A, 1), b":1\r\n").await;
    assert_eq!(
        http_request(http_address, TARGET_B).await,
        hyper::StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        http_request(http_address, TARGET_A).await,
        hyper::StatusCode::OK
    );
    // The same Source value must keep the same Target value across sockets.
    let mut second = TcpStream::connect(address).await.unwrap();
    publish(&mut second, "events", &payload(TARGET_B, 2), ERROR).await;
    publish(&mut second, "events", &payload(TARGET_A, 2), b":2\r\n").await;
    publish(&mut second, "events", &payload(TARGET_B, 3), b":3\r\n").await;
    publish(&mut second, "events", &payload(TARGET_B, 3), ERROR).await;
    let state = state.lock().await;
    assert_eq!(state.http_events.matched_count, 1);
    let report = serde_json::to_value(state.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 3);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        crate::recorder::test_io::read_to_string_sync(case.join("dependencies.jsonl")).unwrap(),
        dependencies
    );
    redis_task.abort();
    http_task.abort();
}

async fn protocol_listeners(
    case: &Path,
    state: std::sync::Arc<tokio::sync::Mutex<crate::replay::ReplayState>>,
) -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    use crate::replay::{ReplayProtocol, http, redis};
    let targets = state.lock().await.targets.clone();
    let redis_target = targets
        .iter()
        .find(|target| target.protocol == ReplayProtocol::Redis)
        .unwrap()
        .clone();
    let http_target = targets
        .iter()
        .find(|target| target.protocol == ReplayProtocol::Http)
        .unwrap()
        .clone();
    let redis_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redis_address = redis_listener.local_addr().unwrap();
    let redis_state = state.clone();
    let redis_task = tokio::spawn(async move {
        loop {
            let (client, _) = redis_listener.accept().await.unwrap();
            let state = redis_state.clone();
            let target = redis_target.clone();
            tokio::spawn(async move {
                let _ = redis::handle_connection(client, target, state).await;
            });
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = listener.local_addr().unwrap();
    let ca = std::sync::Arc::new(
        crate::tls::MitmCa::load_or_generate(
            case.join(".replay/ca.pem"),
            case.join(".replay/ca-key.pem"),
        )
        .unwrap(),
    );
    let http_task = tokio::spawn(async move {
        loop {
            let (client, peer) = listener.accept().await.unwrap();
            let state = state.clone();
            let target = http_target.clone();
            let ca = ca.clone();
            tokio::spawn(async move {
                let _ = http::handle_http_replay_connection(client, peer, target, state, ca).await;
            });
        }
    });
    (redis_address, http_address, redis_task, http_task)
}

#[tokio::test]
async fn unknown_pickle_payload_is_exact_bytes_without_publisher_substring_rewriting() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir_all(&case).unwrap();
    let binary = |id: &str| {
        let mut raw = b"\x80\x04}\x94(\x8c\x07host_id\x94\x8c\x20".to_vec();
        raw.extend_from_slice(id.as_bytes());
        raw.extend_from_slice(b"\x94u.");
        raw
    };
    let mut record = record(Uuid::new_v4(), 1, SOURCE_A, 1);
    record["args"][1] = serde_json::json!({"encoding":"base64","truncated":false,"data":STANDARD.encode(binary(SOURCE_A))});
    std::fs::write(case.join("dependencies.jsonl"), record.to_string()).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/publish"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(&policy,"format: traffic-policy/v3\njson:\n  fields:\n    /host_id: {kind: identity, formats: [{hex: 32}]}\n").unwrap();
    let (address, state, task) = spawn(&case, Some(policy)).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    publish(&mut client, "events", &binary(TARGET_A), ERROR).await;
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 0);
    publish(&mut client, "events", &binary(SOURCE_A), b":1\r\n").await;
    assert_eq!(state.lock().await.redis.snapshot().matched_count, 1);
    task.abort();
}
