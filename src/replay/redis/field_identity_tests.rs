//! Real RESP traffic covers resource identity writes, delivery and finite use.
use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::{Value, json};
use tokio::net::TcpListener;

fn bulk(value: &str) -> Vec<u8> {
    format!("${}\r\n{value}\r\n", value.len()).into_bytes()
}

fn event(sequence: u64, command: &str, args: &[&[u8]], response: &[u8]) -> Value {
    let capture = |bytes: &[u8]| json!({"encoding":"base64", "data":STANDARD.encode(bytes), "truncated":false});
    json!({
        "event_type":"redis_exchange", "connection_id":Uuid::nil(), "sequence":sequence,
        "timestamp":format!("2020-01-01T00:00:{sequence:02}Z"),
        "request_started_at":format!("2020-01-01T00:00:{sequence:02}Z"),
        "duration_ms":0, "outcome":"response", "target_host":"redis.test",
        "target_port":6379, "database":0, "resp_version":2, "command":command,
        "args":args.iter().map(|bytes| capture(bytes)).collect::<Vec<_>>(),
        "response":capture(response), "replay_safe":true,
        "response_kind":if command == "GET" {"bulk_string"} else {"simple_string"}
    })
}

async fn send(client: &mut RedisBufferedReader<TcpStream>, parts: &[&[u8]]) -> Vec<u8> {
    client
        .inner
        .write_all(&crate::redis::encode_array(parts))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), read_redis_frame(client))
        .await
        .unwrap()
        .unwrap()
        .map_or_else(Vec::new, |frame| frame.raw.to_vec())
}

#[tokio::test]
async fn resource_ids_cross_tcp_writes_and_reads_with_native_json_and_finite_inventory() {
    replay_tcp().await;
}

async fn replay_tcp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join(".traffic-e2e/local/artifacts/recordings/run/apis/tasks/case");
    std::fs::create_dir_all(&case).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({
            "method":"POST", "uri":"/tasks", "timestamp":"2020-01-01T00:00:00Z"
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let original_value = r#"{"id":"11","legacy_id":"11","native_nonce":"aaaa","stable":"kept"}"#;
    let historical_value = r#"{"id":"22","stable":"old"}"#;
    let events = [
        event(
            1,
            "SET",
            &[b"session:1", original_value.as_bytes()],
            b"+OK\r\n",
        ),
        event(2, "GET", &[b"session:1"], &bulk(original_value)),
        event(
            3,
            "SET",
            &[b"session:copy", br#"{"id":"11","stable":"copy"}"#],
            b"+OK\r\n",
        ),
        event(4, "GET", &[b"session:historical"], &bulk(historical_value)),
        event(
            5,
            "SET",
            &[
                b"session:historical-copy",
                br#"{"id":"22","stable":"old-copy"}"#,
            ],
            b"+OK\r\n",
        ),
    ];
    let original = events
        .iter()
        .map(|event| format!("{event}\n"))
        .collect::<String>();
    std::fs::write(case.join("dependencies.jsonl"), &original).unwrap();
    let path = root.join(".traffic-e2e/policy.yaml");
    let raw = r#"format: traffic-policy/v3
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
    /legacy_id: {kind: identity, formats: [decimal]}
    /native_nonce: {kind: identity, formats: [{hex: 4}]}
"#;
    let document: Value = serde_yaml::from_str(raw).unwrap();
    std::fs::write(&path, document.to_string()).unwrap();
    crate::replay::write_test_recording_network_manifest(root);
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load_with_lifecycle(
        ReplayConfig {
            case_dir: case.clone(),
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(root.join("ca.pem")),
            ca_key_path: Some(root.join("key.pem")),
            policy_path: Some(path),
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        addr,
        addr,
        Default::default(),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mut task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    let mut client = RedisBufferedReader::new(stream, 1024 * 1024);
    let target_value =
        br#"{"id":"999","legacy_id":"999","native_nonce":"bbbb","stable":"kept"}"#.as_slice();
    assert_eq!(
        send(&mut client, &[b"SET", b"session:1", target_value]).await,
        b"+OK\r\n"
    );
    let delivered = send(&mut client, &[b"GET", b"session:1"]).await;
    assert_eq!(
        delivered,
        bulk(r#"{"id":"999","legacy_id":"999","native_nonce":"bbbb","stable":"kept"}"#)
    );
    assert_eq!(
        send(
            &mut client,
            &[b"SET", b"session:copy", br#"{"id":"999","stable":"copy"}"#]
        )
        .await,
        b"+OK\r\n"
    );
    assert_eq!(
        send(&mut client, &[b"GET", b"session:historical"]).await,
        bulk(historical_value)
    );
    // This input identity was already exposed to Target. It remains anchored
    // even though the candidate write otherwise has the right JSON shape.
    assert_eq!(
        send(
            &mut client,
            &[
                b"SET",
                b"session:historical-copy",
                br#"{"id":"44","stable":"old-copy"}"#
            ]
        )
        .await,
        b""
    );
    task.await.unwrap().unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    task = tokio::spawn(handle_connection(
        server,
        ReplayTarget {
            host: "redis.test".into(),
            port: 6379,
            fake_ip: "198.18.0.1".parse().unwrap(),
            protocol: ReplayProtocol::Redis,
        },
        runtime.state.clone(),
    ));
    client = RedisBufferedReader::new(stream, 1024 * 1024);
    assert_eq!(
        send(
            &mut client,
            &[
                b"SET",
                b"session:historical-copy",
                br#"{"id":"22","stable":"old-copy"}"#
            ]
        )
        .await,
        b"+OK\r\n"
    );
    assert_eq!(send(&mut client, &[b"GET", b"session:1"]).await, b"");
    client.inner.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let state = runtime.state.lock().await;
    let report = state.redis.snapshot();
    assert!(report.unused_case.is_empty(), "{report:?}");
    assert!(report.unsafe_events.is_empty(), "{report:?}");
    assert_eq!(report.matched.len(), 5);
    assert_eq!(report.unmatched.len(), 2);
    assert_eq!(
        crate::recorder::test_io::read_to_string_sync(case.join("dependencies.jsonl")).unwrap(),
        original
    );
}
