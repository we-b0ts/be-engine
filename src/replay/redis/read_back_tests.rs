//! Genuine TCP write/read/reference flow against the ordinary Replay adapter.
use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::{Value, json};
use tokio::net::TcpListener;

fn rule() -> Value {
    json!({"id":"block","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0}}],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
        "proof":{"source":"session.py:1","fact":"Source writes a generated block id, reads the same key and appends using that id"}})
}

fn event(sequence: u64, command: &str, args: &[&[u8]], response: &[u8]) -> Value {
    let capture =
        |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value),"truncated":false});
    json!({"event_type":"redis_exchange","connection_id":Uuid::nil(),"sequence":sequence,
        "timestamp":format!("2020-01-01T00:00:{sequence:02}Z"),"request_started_at":format!("2020-01-01T00:00:{sequence:02}Z"),
        "duration_ms":0,"outcome":"response","target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
        "command":command,"args":args.iter().map(|v|capture(v)).collect::<Vec<_>>(),"response":capture(response),
        "response_kind":if matches!(command,"SET"|"LSET") {"simple_string"}else if command=="GET" {"bulk_string"}else{"integer"},"replay_safe":true})
}

#[tokio::test]
async fn read_back_tcp_preserves_generated_identity_without_target_local_cache() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join(".traffic-e2e/local/artifacts/recordings/run/apis/tasks/case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    let request = json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"});
    std::fs::write(case.join("request.json"), request.to_string()).unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let events = [
        event(1, "SET", &[b"current:7", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:7"], b"$3\r\nold\r\n"),
        event(3, "APPEND", &[b"content:old", b"x"], b":1\r\n"),
        event(
            4,
            "LSET",
            &[
                b"blocks:7",
                b"0",
                br#"{"id":"old","timestamp":1577836804000,"status":"complete"}"#,
            ],
            b"+OK\r\n",
        ),
    ];
    let original = events.iter().map(|v| format!("{v}\n")).collect::<String>();
    std::fs::write(case.join("dependencies.jsonl"), &original).unwrap();
    std::fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        json!({"format":"traffic-policy/v1","rules":[rule(),{
            "id":"lset-time","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"key":{"kind":"exact","value":"blocks:7"}},
            "effect":{"kind":"redis_sequence","commands":[{"operation":"LSET","arguments":{"2":{"kind":"json","fields":{"/timestamp":{"relative_time":"unix_milliseconds"}}}}}]},
            "proof":{"source":"blocks.py:update","fact":"Source writes a millisecond timestamp while preserving a previously bound identity in a list element"}
        }]}).to_string(),
    )
    .unwrap();
    crate::replay::write_test_recording_network_manifest(root);
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = Arc::new(
        ReplayRuntime::load_with_lifecycle(
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
                policy_path: Some(root.join(".traffic-e2e/policy.yaml")),
                http_ignore_query_params: vec![],
                process_owned_dependencies: vec![],
                allowed_unused_http: None,
            },
            addr,
            addr,
            Default::default(),
        )
        .await
        .unwrap(),
    );
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
    let updated =
        json!({"id":"new","timestamp":chrono::Utc::now().timestamp_millis(),"status":"complete"})
            .to_string();
    for (parts, expected) in [
        (
            vec![b"SET".as_slice(), b"current:7", b"new"],
            b"+OK\r\n".as_slice(),
        ),
        (
            vec![b"GET".as_slice(), b"current:7"],
            b"$3\r\nnew\r\n".as_slice(),
        ),
        (
            vec![b"APPEND".as_slice(), b"content:new", b"x"],
            b":1\r\n".as_slice(),
        ),
        (
            vec![b"LSET".as_slice(), b"blocks:7", b"0", updated.as_bytes()],
            b"+OK\r\n".as_slice(),
        ),
    ] {
        client
            .inner
            .write_all(&crate::redis::encode_array(&parts))
            .await
            .unwrap();
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_redis_frame(&mut client),
        )
        .await
        .unwrap()
        .unwrap();
        let frame = match frame {
            Some(frame) => frame,
            None => panic!("Redis handler closed on {parts:?}: {:?}", (&mut task).await),
        };
        assert_eq!(frame.raw.as_ref(), expected);
    }
    // Join the handler after EOF so delivery bookkeeping is complete.
    client.inner.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    let state = runtime.state.lock().await;
    let report = state.redis.snapshot();
    assert!(
        report.unused_case.is_empty()
            && report.unmatched.is_empty()
            && report.unsafe_events.is_empty()
    );
    assert_eq!(
        state
            .replay_policy
            .as_ref()
            .unwrap()
            .report()
            .redis_read_backs
            .len(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(case.join("dependencies.jsonl")).unwrap(),
        original
    );
}
