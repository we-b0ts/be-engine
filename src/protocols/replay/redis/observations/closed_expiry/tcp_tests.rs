//! Genuine RESP clients exercise merged content and zero marker EXPIREs.
use super::*;
use crate::protocols::replay::redis::append::tests::{event, rule as append_rule};
use crate::protocols::replay::redis::observations::tests::{read_rule, refresh_rule};
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn merged_append_over_tcp_closes_initial_marker_ttl_without_any_refresh() {
    exercise_buffering(true).await;
}

#[tokio::test]
async fn split_append_over_tcp_refreshes_marker_when_source_needed_no_refresh() {
    exercise_buffering(false).await;
}

async fn exercise_buffering(source_refresh: bool) {
    let root = tempfile::tempdir().unwrap();
    let case = root
        .path()
        .join(".traffic-e2e/local/artifacts/recordings/run/apis/tasks/case");
    std::fs::create_dir_all(&case).unwrap();
    crate::platform::encryption_key::load_or_create(root.path()).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let events = [
        event(1, "GET", &[b"current:1"], b"$-1\r\n"),
        event(
            2,
            "SET",
            &[b"current:1", b"source", b"EX", b"60"],
            b"+OK\r\n",
        ),
        event(3, "APPEND", &[b"content:source", b"ab"], b":2\r\n"),
        event(4, "GET", &[b"current:1"], b"$6\r\nsource\r\n"),
        event(5, "APPEND", &[b"content:source", b"cd"], b":4\r\n"),
        event(6, "EXPIRE", &[b"current:1", b"60"], b":1\r\n"),
        event(7, "GET", &[b"current:1"], b"$6\r\nsource\r\n"),
        event(8, "GET", &[b"content:source"], b"$4\r\nabcd\r\n"),
        event(9, "DEL", &[b"current:1"], b":1\r\n"),
        event(10, "DEL", &[b"content:source"], b":1\r\n"),
    ];
    let original = events
        .iter()
        .filter(|e| source_refresh || e["command"] != "EXPIRE")
        .map(|e| format!("{e}\n"))
        .collect::<String>();
    std::fs::write(case.join("dependencies.jsonl"), &original).unwrap();
    let mut expiry = refresh_rule();
    expiry["match"]["key"]["prefix"] = json!("current:");
    let policy = root.path().join(".traffic-e2e/policy.yaml");
    std::fs::write(
        &policy,
        json!({"format":"traffic-policy/v3",
        "rules":[read_rule(true), append_rule(), expiry]})
        .to_string(),
    )
    .unwrap();
    crate::replay::write_test_recording_network_manifest(root.path());
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
            ca_cert_path: Some(root.path().join("ca.pem")),
            ca_key_path: Some(root.path().join("key.pem")),
            policy_path: Some(policy),
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
    let task = tokio::spawn(handle_connection(
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
    let mut commands: Vec<(&[&[u8]], &[u8])> = vec![
        (&[b"GET", b"current:1"], b"$-1\r\n"),
        (&[b"SET", b"current:1", b"target", b"EX", b"60"], b"+OK\r\n"),
    ];
    if source_refresh {
        commands.push((&[b"APPEND", b"content:target", b"abcd"], b":4\r\n"));
    } else {
        let split: Vec<(&[&[u8]], &[u8])> = vec![
            (&[b"APPEND", b"content:target", b"ab"], b":2\r\n"),
            (&[b"GET", b"current:1"], b"$6\r\ntarget\r\n"),
            (&[b"EXPIRE", b"current:1", b"60"], b":1\r\n"),
            (&[b"APPEND", b"content:target", b"cd"], b":4\r\n"),
        ];
        commands.extend(split);
    }
    let finish: Vec<(&[&[u8]], &[u8])> = vec![
        (&[b"GET", b"current:1"], b"$6\r\ntarget\r\n"),
        (&[b"GET", b"content:target"], b"$4\r\nabcd\r\n"),
        (&[b"DEL", b"current:1"], b":1\r\n"),
        (&[b"DEL", b"content:target"], b":1\r\n"),
    ];
    commands.extend(finish);
    for (command, expected) in commands {
        client
            .inner
            .write_all(&crate::redis::encode_array(command))
            .await
            .unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(5), read_redis_frame(&mut client))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.raw.as_ref(), expected);
    }
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let report = runtime.state.lock().await.protocols.redis.snapshot();
    assert!(!report.is_dirty(), "{report:?}");
    assert!(report.unused_case.is_empty());
    assert_eq!(
        report.append_streams.len(),
        if source_refresh { 1 } else { 2 }
    );
    let report = serde_json::to_value(report).unwrap();
    let covered = report["state_observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| {
            a["coverage"]["kind"]
                == if source_refresh {
                    "initial_expiry_until_delete"
                } else {
                    "initial_expiry_refresh"
                }
        })
        .unwrap();
    assert_eq!(
        covered["covered_source_observations"],
        usize::from(source_refresh)
    );
    assert_eq!(
        covered["target_event_index"],
        if source_refresh { 5 } else { 4 }
    );
    assert_eq!(
        crate::recorder::test_io::read_to_string_sync(case.join("dependencies.jsonl")).unwrap(),
        original
    );
}
