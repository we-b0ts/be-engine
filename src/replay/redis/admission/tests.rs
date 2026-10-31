use super::*;
use crate::replay::redis::append::tests::{event, request};
use crate::replay::redis::observations::tests::refresh_rule;
use crate::replay::{ReplayConfig, ReplayRuntime};
use serde_json::{Value, json};

pub(super) async fn runtime_with_source(
    events: &[Value],
    document: Value,
) -> (tempfile::TempDir, ReplayRuntime) {
    let root = tempfile::tempdir().unwrap();
    let case = root
        .path()
        .join(".traffic-e2e/local/artifacts/recordings/run/apis/tasks/case");
    std::fs::create_dir_all(&case).unwrap();
    crate::platform::encryption_key::load_or_create(root.path()).unwrap();
    std::fs::write(
        case.join("request.json"),
        json!({
            "method":"POST", "uri":"/tasks", "timestamp":"2020-01-01T00:00:00Z"
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    std::fs::write(
        case.join("dependencies.jsonl"),
        events.iter().map(|e| format!("{e}\n")).collect::<String>(),
    )
    .unwrap();
    let policy = root.path().join("policy.yaml");
    std::fs::write(&policy, document.to_string()).unwrap();
    crate::replay::write_test_recording_network_manifest(root.path());
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load_with_lifecycle(
        ReplayConfig {
            case_dir: case,
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
    (root, runtime)
}

async fn runtime() -> (tempfile::TempDir, ReplayRuntime) {
    let mut events = [
        event(
            1,
            "LRANGE",
            &[b"content:1", b"0", b"-1"],
            b"*1\r\n$3\r\nold\r\n",
        ),
        event(2, "LSET", &[b"content:1", b"0", b"new"], b"+OK\r\n"),
        event(3, "EXPIRE", &[b"content:1", b"60"], b":1\r\n"),
        event(4, "GET", &[b"other"], b"$-1\r\n"),
    ];
    events[0]["response_kind"] = json!("array");
    events[1]["response_kind"] = json!("simple_string");
    events[3]["connection_id"] = json!(Uuid::from_u128(2));
    runtime_with_source(
        &events,
        json!({"format":"traffic-policy/v3", "rules":[refresh_rule()]}),
    )
    .await
}

fn target() -> TargetKey {
    TargetKey {
        host: "redis.test".into(),
        port: 6379,
    }
}

fn expire() -> RedisCommand {
    redis_command(&bytes::Bytes::from(crate::redis::encode_array(&[
        b"EXPIRE",
        b"content:1",
        b"60",
    ])))
    .unwrap()
}

async fn prefix(runtime: &ReplayRuntime) -> MatchedRedisExchange {
    let mut state = runtime.state.lock().await;
    let read = request(&mut state.redis, "LRANGE", &[b"content:1", b"0", b"-1"]).unwrap();
    let write = request(&mut state.redis, "LSET", &[b"content:1", b"0", b"new"]).unwrap();
    state.redis.complete_exchange(&write);
    read
}

#[tokio::test]
async fn refresh_waits_for_read_bookkeeping_and_keeps_its_original_event_and_observation() {
    let (_root, runtime) = runtime().await;
    let read = prefix(&runtime).await;
    let target = target();
    let command = expire();
    let mut binding = CaseConnectionBinding::default();
    let refresh = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut binding,
        2,
        0,
        None,
        &command,
    );
    tokio::pin!(refresh);
    tokio::select! {
        biased;
        result = &mut refresh => panic!("refresh must remain fenced: {result:?}"),
        _ = std::future::ready(()) => {},
    }
    let (clock, observation);
    {
        let mut state = runtime.state.lock().await;
        assert_eq!(
            state.redis.events.request_order.latest(Some("case")),
            Some(2)
        );
        assert!(state.redis.events.unmatched.is_empty());
        clock = state.redis.request_observed_at;
        observation = state.redis.request_observation_id;
        // A different connection may advance the counter while EXPIRE waits.
        let other = request(&mut state.redis, "GET", &[b"other"]).unwrap();
        assert_eq!(other.report.target_event_index, Some(3));
        state.redis.complete_exchange(&other);
        state.redis.complete_exchange(&read);
    }
    let matched = tokio::time::timeout(Duration::from_secs(1), &mut refresh)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(matched.report.target_event_index, Some(2));
    let mut state = runtime.state.lock().await;
    assert_eq!(state.redis.request_observed_at, clock);
    assert_eq!(state.redis.request_observation_id, observation);
    assert_eq!(
        state.redis.events.request_order.latest(Some("case")),
        Some(3)
    );
    state.redis.complete_exchange(&matched);
    let report = serde_json::to_value(state.redis.snapshot()).unwrap();
    assert_eq!(report["state_observations"][0]["target_event_index"], 2);
    assert!(!state.redis.snapshot().is_dirty());
    assert!(state.redis.snapshot().unused_case.is_empty());
}

#[tokio::test]
async fn predecessor_failure_wakes_refresh_and_stays_dirty() {
    exercise_stopped_wait(false).await;
}

#[tokio::test]
async fn waiting_refresh_cannot_match_a_new_case() {
    exercise_stopped_wait(true).await;
}

async fn exercise_stopped_wait(change_case: bool) {
    let (_root, runtime) = runtime().await;
    let read = prefix(&runtime).await;
    let target = target();
    let command = expire();
    let mut binding = CaseConnectionBinding::default();
    let refresh = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut binding,
        2,
        0,
        None,
        &command,
    );
    tokio::pin!(refresh);
    tokio::select! {
        biased;
        result = &mut refresh => panic!("refresh must wait: {result:?}"),
        _ = std::future::ready(()) => {},
    }
    {
        let mut state = runtime.state.lock().await;
        if change_case {
            state.active_case_id = Some("next".into());
            state.redis.complete_exchange(&read);
        } else {
            state.redis.fail_exchange(&read, "transport failed".into());
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), refresh)
            .await
            .unwrap()
            .is_err()
    );
    let state = runtime.state.lock().await;
    assert_eq!(state.redis.events.unmatched.len(), 1);
    assert_eq!(
        state.redis.events.unmatched[0].case_id.as_deref(),
        Some("case")
    );
    assert_eq!(state.redis.events.unmatched[0].target_event_index, Some(2));
    assert!(state.redis.case_is_dirty("case"));
}

#[tokio::test(start_paused = true)]
async fn stalled_predecessor_wait_is_bounded() {
    let (_root, runtime) = runtime().await;
    let _read = prefix(&runtime).await;
    let mut binding = CaseConnectionBinding::default();
    assert!(
        match_command(
            &runtime.state,
            &target(),
            Uuid::new_v4(),
            &mut binding,
            2,
            0,
            None,
            &expire()
        )
        .await
        .is_err()
    );
    let state = runtime.state.lock().await;
    assert!(
        matches!(state.redis.events.unmatched[0].diagnostic.as_ref(),
        Some(CommandMatchDiagnostic::EvidenceUnavailable { reason }) if reason.contains("timed out"))
    );
    assert_eq!(
        state.redis.exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
}

#[tokio::test]
async fn unclaimed_predecessor_is_rejected_without_waiting() {
    let (_root, runtime) = runtime().await;
    let mut binding = CaseConnectionBinding::default();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            match_command(
                &runtime.state,
                &target(),
                Uuid::new_v4(),
                &mut binding,
                2,
                0,
                None,
                &expire(),
            )
        )
        .await
        .unwrap()
        .is_err()
    );
}

#[tokio::test]
async fn responding_read_does_not_hide_an_unclaimed_failed_or_terminating_write() {
    for status in [
        ReplayExchangeStatus::Available,
        ReplayExchangeStatus::Failed,
        ReplayExchangeStatus::AwaitingClientTermination,
    ] {
        let (_root, runtime) = runtime().await;
        let _read = prefix(&runtime).await;
        runtime.state.lock().await.redis.exchanges[1].status = status;
        let mut binding = CaseConnectionBinding::default();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                match_command(
                    &runtime.state,
                    &target(),
                    Uuid::new_v4(),
                    &mut binding,
                    2,
                    0,
                    None,
                    &expire(),
                )
            )
            .await
            .unwrap()
            .is_err()
        );
    }
}

#[tokio::test]
async fn refresh_over_tcp_waits_for_read_completion_then_delivers_the_recorded_response() {
    let (_root, runtime) = runtime().await;
    let read = prefix(&runtime).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    let mut client = RedisBufferedReader::new(stream, 1024);
    client
        .inner
        .write_all(&crate::redis::encode_array(&[
            b"EXPIRE",
            b"content:1",
            b"60",
        ]))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .redis
                .events
                .request_order
                .latest(Some("case"))
                == Some(2)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    {
        let mut state = runtime.state.lock().await;
        assert!(state.redis.events.unmatched.is_empty());
        assert_eq!(state.redis.events.matched_count, 1);
        state.redis.complete_exchange(&read);
    }
    let response = tokio::time::timeout(Duration::from_secs(1), read_redis_frame(&mut client))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.raw.as_ref(), b":1\r\n");
    drop(client);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut state = runtime.state.lock().await;
    let other = request(&mut state.redis, "GET", &[b"other"]).unwrap();
    state.redis.complete_exchange(&other);
    let report = state.redis.snapshot();
    assert!(!report.is_dirty());
    assert!(report.unused_case.is_empty());
}
