use super::*;
use crate::redis::encode_array;
use serde_json::Value;

async fn close_connection(
    client: TcpStream,
    upstream: TcpStream,
    task: tokio::task::JoinHandle<Result<()>>,
) {
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

async fn open_connection(
    state: &AppState,
) -> (TcpStream, TcpStream, tokio::task::JoinHandle<Result<()>>) {
    let (client, proxy) = tcp_pair().await;
    let (upstream, proxy_upstream) = tcp_pair().await;
    let task = spawn_handler(
        proxy,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    (client, upstream, task)
}

async fn subscribe_and_push(client: &mut TcpStream, upstream: &mut TcpStream, command: &str) {
    let response = format!(
        "*3\r\n${}\r\n{}\r\n$6\r\nevents\r\n:1\r\n",
        command.len(),
        command.to_ascii_lowercase()
    );
    forward_test_exchange(
        client,
        upstream,
        &encode_array(&[command.as_bytes(), b"events"]),
        response.as_bytes(),
    )
    .await;
    let push = match command {
        "PSUBSCRIBE" => encode_array(&[b"pmessage", b"events", b"events", b"payload"]),
        "SSUBSCRIBE" => encode_array(&[b"smessage", b"events", b"payload"]),
        _ => encode_array(&[b"message", b"events", b"payload"]),
    };
    upstream.write_all(&push).await.unwrap();
    let mut received = vec![0; push.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, push);
}

async fn global_events(state: &AppState) -> Vec<Value> {
    state.recorder().flush_all_dependency_files().await.unwrap();
    let path = state.recorder().run_dir.join("global-dependencies.jsonl");
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => raw
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("failed to read Global evidence: {error}"),
    }
}

#[tokio::test]
async fn subscriptions_keep_bootstrap_case_idle_and_reconnect_evidence_without_duplicates() {
    for command in ["SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE"] {
        let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
        let (mut bootstrap, mut upstream, task) = open_connection(&state).await;
        subscribe_and_push(&mut bootstrap, &mut upstream, command).await;
        close_connection(bootstrap, upstream, task).await;

        let case = test_case("subscription-case");
        let guard = state.try_reserve_active_case(case.clone()).unwrap();
        state.activate_case_dependencies(&guard).unwrap();
        let (mut client, mut upstream, task) = open_connection(&state).await;
        subscribe_and_push(&mut client, &mut upstream, command).await;
        drop(guard);
        // A real repeated confirmation replaces the anchor even while idle.
        subscribe_and_push(&mut client, &mut upstream, command).await;
        close_connection(client, upstream, task).await;
        let (mut reconnect, mut upstream, task) = open_connection(&state).await;
        subscribe_and_push(&mut reconnect, &mut upstream, command).await;
        close_connection(reconnect, upstream, task).await;

        let events = global_events(&state).await;
        let subscriptions: Vec<_> = events
            .iter()
            .filter(|event| event["event_type"] == "redis_exchange")
            .collect();
        let pushes: Vec<_> = events
            .iter()
            .filter(|event| event["event_type"] == "redis_pub_sub_push")
            .collect();
        assert_eq!(subscriptions.len(), 4);
        assert_eq!(pushes.len(), 4);
        assert_eq!(
            subscriptions[0]["global_dependency_reason"],
            "bootstrap_window"
        );
        assert_eq!(subscriptions[0]["global_dependency_phase"], "bootstrap");
        assert_eq!(
            subscriptions[1]["global_dependency_reason"],
            "pubsub_subscription_mirror"
        );
        for subscription in &subscriptions[2..] {
            assert_eq!(
                subscription["global_dependency_reason"],
                "pubsub_subscription"
            );
            assert_eq!(subscription["global_dependency_phase"], "runtime");
        }
        assert_eq!(
            subscriptions[1]["connection_id"],
            subscriptions[2]["connection_id"]
        );
        assert_ne!(
            subscriptions[2]["connection_id"],
            subscriptions[3]["connection_id"]
        );
        assert_eq!(subscriptions[2]["sequence"], 2);
        assert_eq!(subscriptions[3]["sequence"], 1);
        for (subscription, push) in subscriptions.iter().zip(pushes) {
            assert_eq!(subscription["connection_id"], push["connection_id"]);
            assert_eq!(subscription["sequence"], push["subscription_sequence"]);
            assert_eq!(subscription["replay_safe"], true);
            let confirmation_position = events
                .iter()
                .position(|event| std::ptr::eq(event, *subscription))
                .unwrap();
            let push_position = events
                .iter()
                .position(|event| std::ptr::eq(event, push))
                .unwrap();
            assert!(confirmation_position < push_position);
        }

        let raw = tokio::fs::read_to_string(
            state
                .recorder()
                .case_staging_dir(&case)
                .join("dependencies.jsonl"),
        )
        .await
        .unwrap();
        let case_exchanges: Vec<Value> = raw
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["event_type"] == "redis_exchange")
            .collect();
        assert_eq!(case_exchanges.len(), 1);
        let mut original = case_exchanges[0].clone();
        original
            .as_object_mut()
            .unwrap()
            .remove("case_dependency_matched_by");
        let mut mirror = subscriptions[1].clone();
        for field in [
            "global_dependency_reason",
            "global_dependency_phase",
            "global_dependency_matched_by",
        ] {
            mirror.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(
            original, mirror,
            "the mirror must preserve the exact original event"
        );
    }
}

#[tokio::test]
async fn invalid_subscription_confirmations_never_replace_the_last_real_anchor() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let case = test_case("invalid-subscriptions");
    let guard = state.try_reserve_active_case(case).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let (mut client, mut upstream, task) = open_connection(&state).await;
    subscribe_and_push(&mut client, &mut upstream, "SUBSCRIBE").await;
    for (command, response) in [
        (
            "SUBSCRIBE",
            b"*3\r\n$9\r\nsubscribe\r\n$5\r\nother\r\n:1\r\n".as_slice(),
        ),
        ("UNSUBSCRIBE", b"-ERR denied\r\n".as_slice()),
        (
            "UNSUBSCRIBE",
            b"*3\r\n$11\r\nunsubscribe\r\n$5\r\nother\r\n:0\r\n".as_slice(),
        ),
    ] {
        forward_test_exchange(
            &mut client,
            &mut upstream,
            &encode_array(&[command.as_bytes(), b"events"]),
            response,
        )
        .await;
        let push = encode_array(&[b"message", b"events", b"still-subscribed"]);
        upstream.write_all(&push).await.unwrap();
        let mut received = vec![0; push.len()];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, push);
    }
    close_connection(client, upstream, task).await;
    let events = global_events(&state).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event_type"] == "redis_exchange")
            .count(),
        1
    );
    let pushes: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "redis_pub_sub_push")
        .collect();
    assert_eq!(pushes.len(), 4);
    assert!(pushes.iter().all(|push| push["subscription_sequence"] == 1));
}

#[tokio::test]
async fn truncated_confirmation_is_never_published_as_subscription_proof() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let case = test_case("truncated-subscription");
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let pending = PendingRedisExchange {
        targets: state.capture_dependency_targets(),
        sequence: 1,
        command: RedisCommand {
            name: "SUBSCRIBE".to_string(),
            args: vec![b"events".to_vec()],
        },
        recorded_args: vec![b"events".to_vec()],
        session: RedisSession {
            resp_version: 2,
            database: 0,
            username: None,
            subscriptions: pubsub::Subscriptions::default(),
        },
        session_setup: false,
        replay_safe: true,
        warnings: Vec::new(),
        cache_snapshot_rule: None,
        cache_snapshot_key: None,
        cache_snapshot_hit: false,
        started: Instant::now(),
    };
    record_exchange(
        &state,
        Uuid::new_v4(),
        &ConnectionContext {
            client_addr: None,
            target_host: "redis.test".to_string(),
            target_port: 6379,
            target_addr: "redis.test:6379".to_string(),
            upstream_addr: "127.0.0.1:6379".to_string(),
        },
        pending,
        RedisFrameKind::Array,
        b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n",
        DependencyExchangeOutcome::Response,
        8,
    )
    .await
    .unwrap();
    assert!(global_events(&state).await.is_empty());
    let raw = tokio::fs::read_to_string(
        state
            .recorder()
            .case_staging_dir(&case)
            .join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let event: Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
    assert_eq!(event["replay_safe"], false);
    assert_eq!(event["response"]["truncated"], true);
}
