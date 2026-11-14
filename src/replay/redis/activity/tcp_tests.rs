//! Genuine RESP delivery validates refreshes and preserves an ordinary finite trace.
use super::*;
use crate::replay::{ReplayConfig, ReplayRuntime};
use std::fs;
use tokio::net::TcpListener;

#[tokio::test]
async fn activity_refresh_tcp_supports_split_merge_and_unchanged_finite_trace() {
    for (enabled, chunks) in [
        (true, vec![b"abcd".as_slice()]),
        (true, vec![b"a".as_slice(), b"b", b"c", b"d"]),
        (false, vec![b"ab".as_slice(), b"cd"]),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let case = root.join(".traffic-e2e/local/artifacts/recordings/run/apis/tasks/case");
        fs::create_dir_all(&case).unwrap();
        crate::platform::encryption_key::load_or_create(root).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::json!({"method":"POST","uri":"/tasks","timestamp":"2020-01-01T00:00:00Z"})
                .to_string(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();
        let original = events()
            .iter()
            .map(|e| format!("{e}\n"))
            .collect::<String>();
        fs::write(case.join("dependencies.jsonl"), &original).unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        fs::write(&policy, document(enabled).to_string()).unwrap();
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
            .unwrap(),
        );
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
        let mut client = RedisBufferedReader::new(stream, MAX_BYTES);
        let now = now_string();
        let mut current = object(&now, &now);
        assert_eq!(
            exchange(
                &mut client,
                &[b"SET", b"activity:1", &current, b"EX", b"3600"]
            )
            .await,
            b"+OK\r\n"
        );
        let mut offset = 0;
        for chunk in chunks {
            offset += chunk.len();
            assert_eq!(
                exchange(&mut client, &[b"APPEND", b"content:1", chunk]).await,
                format!(":{offset}\r\n").as_bytes()
            );
            assert_eq!(
                exchange(&mut client, &[b"GET", b"activity:1"]).await,
                value::bulk(&current)
            );
            let mut next: Value = serde_json::from_slice(&current).unwrap();
            next["last_activity_at"] = serde_json::json!(now_string());
            current = serde_json::to_vec(&next).unwrap();
            assert_eq!(
                exchange(
                    &mut client,
                    &[b"SET", b"activity:1", &current, b"EX", b"3600"]
                )
                .await,
                b"+OK\r\n"
            );
        }
        assert_eq!(
            exchange(&mut client, &[b"DEL", b"activity:1"]).await,
            b":1\r\n"
        );
        assert_eq!(
            exchange(&mut client, &[b"GET", b"content:1"]).await,
            b"$4\r\nabcd\r\n"
        );
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let state = runtime.state.lock().await;
        let report = state.protocols.redis.snapshot();
        assert!(!report.is_dirty(), "{report:?}");
        assert!(report.unused_case.is_empty());
        assert!(!state.protocols.redis.has_case_in_flight());
        assert_eq!(
            fs::read_to_string(case.join("dependencies.jsonl")).unwrap(),
            original
        );
    }
}

async fn exchange(client: &mut RedisBufferedReader<TcpStream>, parts: &[&[u8]]) -> Vec<u8> {
    client
        .inner
        .write_all(&crate::redis::encode_array(parts))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), read_redis_frame(client))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .raw
        .to_vec()
}
