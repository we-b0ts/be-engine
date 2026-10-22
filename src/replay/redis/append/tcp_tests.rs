//! Ordinary TCP clients exercise stream chunks interleaved with finite expiry operations.
use super::tests::{event, rule};
use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn append_tcp_replays_changed_batches_and_exact_final_read() {
    replay_tcp(false, false, None).await;
}

#[tokio::test]
async fn rejected_tcp_request_and_successes_share_arrival_indices() {
    replay_tcp(true, false, None).await;
}

#[tokio::test]
async fn nil_poll_reads_commute_with_append_batches_over_real_tcp() {
    replay_tcp(false, true, None).await;
}

#[tokio::test]
async fn state_observations_support_split_batches_over_real_tcp() {
    replay_tcp(false, false, Some(&[b"a", b"b", b"cd"])).await;
}

#[tokio::test]
async fn state_observations_support_merged_batches_over_real_tcp() {
    replay_tcp(false, false, Some(&[b"abcd"])).await;
}

async fn replay_tcp(reject_first: bool, commute_reads: bool, observation_chunks: Option<&[&[u8]]>) {
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
    let mut events = vec![
        event(1, "SET", &[b"current:7", b"old"], b"+OK\r\n"),
        event(2, "GET", &[b"current:7"], b"$3\r\nold\r\n"),
        event(3, "APPEND", &[b"content:old", b"ab"], b":2\r\n"),
        event(4, "EXPIRE", &[b"content:old", b"3600"], b":1\r\n"),
        event(5, "APPEND", &[b"content:old", b"cd"], b":4\r\n"),
        event(6, "EXPIRE", &[b"content:old", b"3600"], b":1\r\n"),
        event(7, "GET", &[b"content:old"], b"$4\r\nabcd\r\n"),
    ];
    if commute_reads {
        events.insert(2, event(3, "GET", &[b"cancel:7"], b"$-1\r\n"));
        events.push(event(9, "GET", &[b"cancel:7"], b"$-1\r\n"));
        for (index, event) in events.iter_mut().enumerate() {
            event["sequence"] = json!(index + 1);
        }
    }
    if observation_chunks.is_some() {
        events.insert(4, event(5, "GET", &[b"current:7"], b"$3\r\nold\r\n"));
        for (index, event) in events.iter_mut().enumerate() {
            event["sequence"] = json!(index + 1);
        }
    }
    let original = events.iter().map(|e| format!("{e}\n")).collect::<String>();
    std::fs::write(case.join("dependencies.jsonl"), &original).unwrap();
    let mut identity = json!({"id":"block","match":{"api":"POST /tasks","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"operation":"SET","key":{"kind":"affix","prefix":"current:"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},
            "references":[{"resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0}}],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1}]},
        "proof":{"source":"session.py:1","fact":"Source writes a generated block id, reads it and uses it in content keys"}});
    if observation_chunks.is_some() {
        identity["effect"]["read_back"][0]["state_epochs"] = json!({"source":"session.py:5","fact":"Source reads the Case current identity between SET/DEL transitions; batch scheduling only changes the read count"});
    }
    let mut rules = vec![identity, rule()];
    if observation_chunks.is_some() {
        rules.push(crate::replay::redis::observations::tests::refresh_rule());
    }
    if commute_reads {
        rules.push(crate::replay::redis::read_commutation::tests::rule());
    }
    std::fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        json!({"format":"traffic-policy/v1","rules":rules}).to_string(),
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
    if reject_first {
        client
            .inner
            .write_all(&crate::redis::encode_array(&[b"GET", b"unrecorded"]))
            .await
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_redis_frame(&mut client),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(
            response.raw.as_ref(),
            b"-ERR no recorded Redis dependency matched\r\n"
        );
    }
    let chunks = observation_chunks.unwrap_or(&[b"a", b"bcd"]);
    let mut requests: Vec<(Vec<&[u8]>, Vec<u8>)> =
        vec![(vec![b"SET", b"current:7", b"new"], b"+OK\r\n".to_vec())];
    let mut offset = 0;
    for (index, chunk) in chunks.iter().enumerate() {
        if index == 0 || observation_chunks.is_some() {
            requests.push((vec![b"GET", b"current:7"], b"$3\r\nnew\r\n".to_vec()));
        }
        offset += chunk.len();
        requests.push((
            vec![b"APPEND", b"content:new", chunk],
            format!(":{offset}\r\n").into_bytes(),
        ));
        requests.push((vec![b"EXPIRE", b"content:new", b"3600"], b":1\r\n".to_vec()));
    }
    requests.push((vec![b"GET", b"content:new"], b"$4\r\nabcd\r\n".to_vec()));
    for (parts, expected) in requests {
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
        assert_eq!(frame.raw.as_ref(), expected.as_slice());
    }
    if commute_reads {
        // Source polls precede the flush. Target polls arrive after both batches.
        for _ in 0..2 {
            client
                .inner
                .write_all(&crate::redis::encode_array(&[b"GET", b"cancel:7"]))
                .await
                .unwrap();
            let frame = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_redis_frame(&mut client),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert_eq!(frame.raw.as_ref(), b"$-1\r\n");
        }
    }
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let state = runtime.state.lock().await;
    let report = state.redis.snapshot();
    assert_eq!(report.is_dirty(), reject_first, "{report:?}");
    assert_eq!(report.unmatched.len(), usize::from(reject_first));
    if reject_first {
        assert_eq!(report.unmatched[0].target_event_index, Some(0));
    }
    assert!(report.unused_case.is_empty());
    assert!(report.unsupported.is_empty());
    assert!(report.unsafe_events.is_empty());
    for (index, matched) in report.matched.iter().enumerate() {
        assert_eq!(
            matched.target_event_index,
            Some(index + usize::from(reject_first))
        );
    }
    assert_eq!(report.append_streams.len(), chunks.len());
    if observation_chunks.is_some() {
        assert!(!report.state_observations.is_empty());
    }
    let policy = state.replay_policy.as_ref().unwrap().report();
    assert_eq!(
        policy.redis_read_backs.len(),
        if observation_chunks.is_some() {
            chunks.len()
        } else {
            1
        }
    );
    if commute_reads {
        assert_eq!(
            policy
                .dependency_rules
                .iter()
                .find(|r| r.id == "poll")
                .unwrap()
                .matches,
            2
        );
    }
    assert_eq!(
        policy
            .dependency_rules
            .iter()
            .find(|r| r.id == "append")
            .unwrap()
            .matches,
        chunks.len()
    );
    assert_eq!(
        std::fs::read_to_string(case.join("dependencies.jsonl")).unwrap(),
        original
    );
}
