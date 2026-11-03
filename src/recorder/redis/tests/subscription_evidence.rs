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

async fn recorded_events(state: &AppState) -> Vec<Value> {
    state.recorder().flush_all_dependency_files().await.unwrap();
    let path = state.recorder().run_dir.join("dependencies.jsonl");
    match crate::recorder::test_io::read_to_string(path).await {
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

        let events = recorded_events(&state).await;
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
        assert_eq!(pushes[0]["capture"]["attribution"]["kind"], "startup");
        assert_eq!(
            pushes[1]["capture"]["attribution"]["origin_case_id"],
            case.id.to_string()
        );
        assert!(
            pushes[2..]
                .iter()
                .all(|push| push["capture"]["attribution"]["kind"] == "unattributed")
        );
        assert_eq!(
            subscriptions[0]["capture"]["attribution"]["kind"],
            "startup"
        );
        assert_eq!(subscriptions[0]["capture"]["phase"], "startup");
        assert_eq!(subscriptions[1]["capture"]["attribution"]["kind"], "case");
        for subscription in &subscriptions[2..] {
            assert_eq!(
                subscription["capture"]["attribution"]["kind"],
                "unattributed"
            );
            assert_eq!(subscription["capture"]["phase"], "runtime");
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

        state
            .recorder()
            .flush_case_dependency_files(&state.recorder().case_staging_dir(&case))
            .await
            .unwrap();
        let raw = crate::recorder::test_io::read_to_string(
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
        assert_eq!(
            case_exchanges[0], *subscriptions[1],
            "the scope refers to the single immutable exchange"
        );
    }
}

#[tokio::test]
async fn declared_process_pubsub_does_not_borrow_a_running_case() {
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config
        .process_dependency_tasks
        .insert("subscriber".into(), "receive_loop".into());
    config.process_owned_dependencies.push(
        serde_yaml::from_str(
            r#"
protocol: redis_pubsub
name: subscriber
selector:
  resource: {protocol: redis, endpoint: 'redis.test:6379', database: 0}
  channel: events
  kind: message
source_evidence: subscriber.py:receive
"#,
        )
        .unwrap(),
    );
    let state = AppState::new(config).await.unwrap();
    let case = test_case("active-api");
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let (mut client, mut upstream, task) = open_connection(&state).await;
    subscribe_and_push(&mut client, &mut upstream, "SUBSCRIBE").await;
    close_connection(client, upstream, task).await;
    let events = recorded_events(&state).await;
    let push = events
        .iter()
        .find(|event| event["event_type"] == "redis_pub_sub_push")
        .unwrap();
    assert_eq!(push["capture"]["attribution"]["kind"], "process");
    assert_eq!(
        push["capture"]["attribution"]["source_task"],
        "receive_loop"
    );
    assert_eq!(push["capture"]["observed_case"], case.id.to_string());
    let subscription = events
        .iter()
        .find(|event| event["command"] == "SUBSCRIBE")
        .unwrap();
    assert_eq!(subscription["capture"]["attribution"]["kind"], "case");
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
    let events = recorded_events(&state).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event_type"] == "redis_exchange")
            .count(),
        4
    );
    let complete_exchanges = events
        .iter()
        .filter(|event| event["event_type"] == "redis_exchange" && event["replay_safe"] == true)
        .count();
    // A rejected command is still complete replay evidence. It cannot replace
    // the last successful subscription anchor used by any subsequent push.
    assert_eq!(complete_exchanges, 2);
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
        request_started_at: Utc::now(),
        ended_at: None,
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
    let events = recorded_events(&state).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event_type"] == "redis_exchange")
            .count(),
        1
    );
    state
        .recorder()
        .flush_case_dependency_files(&state.recorder().case_staging_dir(&case))
        .await
        .unwrap();
    let raw = crate::recorder::test_io::read_to_string(
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
