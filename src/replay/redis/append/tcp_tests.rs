//! Ordinary TCP clients exercise stream chunks interleaved with finite expiry operations.
use super::tests::{event, rule};
use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn append_tcp_replays_changed_batches_and_exact_final_read() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join(".traffic-e2e/local/artifacts/recordings/run/apis/tasks/case");
    std::fs::create_dir_all(&case).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let events = [
        event(1, "SET", &[b"current:7", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:7"], b"$3\r\nold\r\n"),
        event(3, "APPEND", &[b"content:old", b"ab"], b":2\r\n"),
        event(4, "EXPIRE", &[b"content:old", b"3600"], b":1\r\n"),
        event(5, "APPEND", &[b"content:old", b"cd"], b":4\r\n"),
        event(6, "EXPIRE", &[b"content:old", b"3600"], b":1\r\n"),
        event(7, "GET", &[b"content:old"], b"$4\r\nabcd\r\n"),
    ];
    let original = events.iter().map(|e| format!("{e}\n")).collect::<String>();
    std::fs::write(case.join("dependencies.jsonl"), &original).unwrap();
    let identity = json!({"id":"block","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0}}],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
        "proof":{"source":"session.py:1","fact":"Source writes a generated block id, reads it and uses it in content keys"}});
    std::fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        json!({"format":"traffic-policy/v1","rules":[identity,rule()]}).to_string(),
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
            vec![b"APPEND".as_slice(), b"content:new", b"a"],
            b":1\r\n".as_slice(),
        ),
        (
            vec![b"EXPIRE".as_slice(), b"content:new", b"3600"],
            b":1\r\n".as_slice(),
        ),
        (
            vec![b"APPEND".as_slice(), b"content:new", b"bcd"],
            b":4\r\n".as_slice(),
        ),
        (
            vec![b"EXPIRE".as_slice(), b"content:new", b"3600"],
            b":1\r\n".as_slice(),
        ),
        (
            vec![b"GET".as_slice(), b"content:new"],
            b"$4\r\nabcd\r\n".as_slice(),
        ),
    ] {
        let request = crate::redis::encode_array(&parts);
        client.inner.write_all(&request).await.unwrap();
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_redis_frame(&mut client),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(frame.raw.as_ref(), expected);
    }
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let state = runtime.state.lock().await;
    let report = state.redis.snapshot();
    assert!(!report.is_dirty(), "{report:?}");
    assert_eq!(report.append_streams.len(), 2);
    let policy = state.replay_policy.as_ref().unwrap().report();
    assert_eq!(policy.redis_read_backs.len(), 1);
    assert_eq!(
        policy
            .dependency_rules
            .iter()
            .find(|r| r.id == "append")
            .unwrap()
            .matches,
        2
    );
    assert_eq!(
        std::fs::read_to_string(case.join("dependencies.jsonl")).unwrap(),
        original
    );
}
