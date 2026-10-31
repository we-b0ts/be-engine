use std::os::fd::AsRawFd;
use std::time::Duration;

use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::recorder::CaseContext;
use crate::{AppConfig, BackgroundDependencyRuleConfig, RecordingAccessPolicy};

use super::*;

mod finite_get;
mod termination;

#[test]
fn authentication_secrets_are_never_recorded() {
    let auth = RedisCommand {
        name: "AUTH".to_string(),
        args: vec![b"alice".to_vec(), b"super-secret".to_vec()],
    };
    let (args, session_setup, replay_safe, _) = sanitize_and_classify(&auth);
    assert_eq!(args, vec![b"alice".to_vec(), b"<redacted>".to_vec()]);
    assert!(session_setup);
    assert!(replay_safe);

    let hello = RedisCommand {
        name: "HELLO".to_string(),
        args: vec![
            b"3".to_vec(),
            b"AUTH".to_vec(),
            b"alice".to_vec(),
            b"another-secret".to_vec(),
        ],
    };
    let (args, _, _, _) = sanitize_and_classify(&hello);
    assert_eq!(args[2], b"alice");
    assert_eq!(args[3], b"<redacted>");
}

#[test]
fn only_single_subscription_confirmations_are_classified_as_replay_safe() {
    let single = RedisCommand {
        name: "PSUBSCRIBE".to_string(),
        args: vec![b"/0.celery.pidbox".to_vec()],
    };
    let (_, _, replay_safe, warnings) = sanitize_and_classify(&single);
    assert!(replay_safe);
    assert!(warnings.is_empty());

    let multiple = RedisCommand {
        name: "SUBSCRIBE".to_string(),
        args: vec![b"one".to_vec(), b"two".to_vec()],
    };
    let (_, _, replay_safe, warnings) = sanitize_and_classify(&multiple);
    assert!(!replay_safe);
    assert!(warnings[0].contains("exactly one"));

    let unsubscribe = RedisCommand {
        name: "PUNSUBSCRIBE".to_string(),
        args: vec![b"events.*".to_vec()],
    };
    let (_, _, replay_safe, warnings) = sanitize_and_classify(&unsubscribe);
    assert!(replay_safe);
    assert!(warnings.is_empty());

    for args in [vec![], vec![b"one".to_vec(), b"two".to_vec()]] {
        let unsubscribe = RedisCommand {
            name: "UNSUBSCRIBE".to_string(),
            args,
        };
        let (_, _, replay_safe, warnings) = sanitize_and_classify(&unsubscribe);
        assert!(!replay_safe);
        assert!(warnings[0].contains("exactly one"));
    }
}

#[tokio::test]
async fn single_subscription_confirmation_is_recorded_as_replay_safe() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*2\r\n$10\r\nPSUBSCRIBE\r\n$16\r\n/0.celery.pidbox\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    let response = b"*3\r\n$10\r\npsubscribe\r\n$16\r\n/0.celery.pidbox\r\n:1\r\n";
    upstream.write_all(response).await.unwrap();
    let mut received_response = vec![0_u8; response.len()];
    client.read_exact(&mut received_response).await.unwrap();
    assert_eq!(received_response, response);

    client.shutdown().await.unwrap();
    drop(client);
    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let raw =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    let exchange = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["command"], "PSUBSCRIBE");
    assert_eq!(exchange["response_kind"], "array");
    assert_eq!(exchange["replay_safe"], true);
    assert_eq!(exchange["parse_warnings"], serde_json::json!([]));
}

#[tokio::test]
async fn subscribed_push_is_forwarded_without_degrading_capture() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$6\r\nevents\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n";
    let push = b"*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$7\r\npayload\r\n";
    upstream.write_all(confirmation).await.unwrap();
    upstream.write_all(push).await.unwrap();
    let mut received = vec![0_u8; confirmation.len() + push.len()];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(
        received,
        [confirmation.as_slice(), push.as_slice()].concat()
    );

    client.shutdown().await.unwrap();
    drop(client);
    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let traffic =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    assert!(!traffic.contains("proxy_error"));
}

#[tokio::test]
async fn unsubscribed_array_that_looks_like_a_push_remains_a_response() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    let request = b"*4\r\n$6\r\nLRANGE\r\n$3\r\nkey\r\n$1\r\n0\r\n$2\r\n-1\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    let response = b"*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$7\r\npayload\r\n";
    upstream.write_all(response).await.unwrap();
    let mut received_response = vec![0_u8; response.len()];
    client.read_exact(&mut received_response).await.unwrap();
    assert_eq!(received_response, response);

    client.shutdown().await.unwrap();
    drop(client);
    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn unsubscription_restores_ordinary_responses_and_keeps_case_dependencies_safe() {
    for (subscribe, unsubscribe) in [
        ("SUBSCRIBE", "UNSUBSCRIBE"),
        ("PSUBSCRIBE", "PUNSUBSCRIBE"),
        ("SSUBSCRIBE", "SUNSUBSCRIBE"),
    ] {
        let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
        let case = test_case("celery-trigger");
        let guard = state.try_reserve_active_case(case.clone()).unwrap();
        state.activate_case_dependencies(&guard).unwrap();
        let (mut client, proxy_client) = tcp_pair().await;
        let (mut upstream, proxy_upstream) = tcp_pair().await;
        let upstream_addr = upstream.peer_addr().unwrap();
        let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);
        let subject = "celery-task-meta-task-id";

        for (command, count) in [(subscribe, 1), (unsubscribe, 0)] {
            let request = format!(
                "*2\r\n${}\r\n{command}\r\n${}\r\n{subject}\r\n",
                command.len(),
                subject.len()
            );
            let response = format!(
                "*3\r\n${}\r\n{}\r\n${}\r\n{subject}\r\n:{count}\r\n",
                command.len(),
                command.to_ascii_lowercase(),
                subject.len()
            );
            forward_test_exchange(
                &mut client,
                &mut upstream,
                request.as_bytes(),
                response.as_bytes(),
            )
            .await;
        }

        // Once the last subscription is removed, this LRANGE array is ordinary
        // business data even though its shape resembles a Pub/Sub notification.
        forward_test_exchange(
            &mut client,
            &mut upstream,
            b"*4\r\n$6\r\nLRANGE\r\n$3\r\nkey\r\n$1\r\n0\r\n$2\r\n-1\r\n",
            b"*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$7\r\npayload\r\n",
        )
        .await;

        client.shutdown().await.unwrap();
        drop(client);
        let mut eof = [0_u8; 1];
        assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
        drop(upstream);
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        state.recorder().flush_traffic().await.unwrap();
        assert_eq!(
            state
                .recorder()
                .case_dependency_safety_issue(&case)
                .await
                .unwrap(),
            None
        );
        let semantic = crate::recorder::test_io::read_to_string(
            state
                .recorder()
                .case_staging_dir(&case)
                .join("dependencies.jsonl"),
        )
        .await
        .unwrap();
        let exchanges = semantic
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|value| value["event_type"] == "redis_exchange")
            .collect::<Vec<_>>();
        assert_eq!(exchanges.len(), 3);
        assert_eq!(exchanges[0]["command"], subscribe);
        assert_eq!(exchanges[1]["command"], unsubscribe);
        assert_eq!(exchanges[2]["command"], "LRANGE");
        for exchange in exchanges {
            assert_eq!(exchange["replay_safe"], true);
            assert_eq!(exchange["parse_warnings"], serde_json::json!([]));
        }
    }
}

async fn forward_test_exchange(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    request: &[u8],
    response: &[u8],
) {
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        upstream.read_exact(&mut received_request),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received_request, request);
    upstream.write_all(response).await.unwrap();
    let mut received_response = vec![0_u8; response.len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client.read_exact(&mut received_response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received_response, response);
}

#[tokio::test]
async fn blocked_write_returns_ordered_error_without_reaching_upstream() {
    let (state, _temp) = test_state(RecordingAccessPolicy::BlockKnownWrites).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    client
        .write_all(b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n")
        .await
        .unwrap();
    let mut response = [0_u8; 128];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&response[..read]).starts_with("-READONLY"));

    let mut probe = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.read(&mut probe))
            .await
            .is_err()
    );
    handler.abort();
}

#[tokio::test]
async fn background_read_reuses_the_first_successful_response_for_the_run() {
    let (state, _temp) = snapshot_test_state().await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    let response = b"$2\r\nv1\r\n";
    client.write_all(request).await.unwrap();
    let mut first_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut first_request).await.unwrap();
    upstream.write_all(response).await.unwrap();
    let mut first_response = vec![0_u8; response.len()];
    client.read_exact(&mut first_response).await.unwrap();
    assert_eq!(first_response, response);

    client.write_all(request).await.unwrap();
    let mut second_response = vec![0_u8; response.len()];
    client.read_exact(&mut second_response).await.unwrap();
    assert_eq!(second_response, response);
    let mut unexpected_upstream = [0_u8; 1];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            upstream.read(&mut unexpected_upstream)
        )
        .await
        .is_err(),
        "the second matching read must not reach the real cache"
    );

    client.shutdown().await.unwrap();
    drop(client);
    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let raw =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    let exchanges = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value["event_type"] == "redis_exchange")
        .collect::<Vec<_>>();
    assert_eq!(exchanges.len(), 2);
    assert_eq!(exchanges[0]["cache_snapshot_rule"], "snapshot-get");
    assert!(exchanges[0].get("cache_snapshot_hit").is_none());
    assert_eq!(exchanges[1]["cache_snapshot_rule"], "snapshot-get");
    assert_eq!(exchanges[1]["cache_snapshot_hit"], true);

    state
        .recorder()
        .flush_global_dependency_files()
        .await
        .unwrap();
    let semantic = crate::recorder::test_io::read_to_string(
        state.recorder().run_dir.join("indexes/process-scope.json"),
    )
    .await
    .unwrap();
    assert_eq!(
        semantic
            .lines()
            .filter(|line| line.contains("\"event_type\":\"redis_exchange\""))
            .count(),
        2,
        "seed and reuse remain immutable observations"
    );
}

#[tokio::test]
async fn completed_exchange_accepts_abortive_client_close() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    let response = b"$5\r\nvalue\r\n";
    upstream.write_all(response).await.unwrap();
    let mut received_response = vec![0_u8; response.len()];
    client.read_exact(&mut received_response).await.unwrap();
    assert_eq!(received_response, response);

    enable_abortive_close(&client);
    drop(client);

    let mut eof = [0_u8; 1];
    assert_eq!(
        upstream.read(&mut eof).await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionReset
    );
    drop(upstream);

    let result = tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test]
async fn pending_exchange_records_client_termination_as_replay_safe() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    client.shutdown().await.unwrap();
    drop(client);

    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let raw =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    let exchange = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["outcome"]["terminated"]["side"], "client");
    assert_eq!(exchange["response"]["original_len"], 0);
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 50);
}

#[tokio::test]
async fn pending_quit_is_a_safe_control_fact_with_no_business_consumption_slot() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = b"*1\r\n$4\r\nQUIT\r\n";
    client.write_all(request).await.unwrap();
    let mut received_request = vec![0_u8; request.len()];
    upstream.read_exact(&mut received_request).await.unwrap();
    assert_eq!(received_request, request);

    drop(upstream);
    tokio::time::sleep(Duration::from_millis(20)).await;
    client.shutdown().await.unwrap();
    drop(client);

    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    state.recorder().flush_traffic().await.unwrap();
    let raw =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    let events = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    let exchange = events
        .iter()
        .find(|value| value["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["command"], "QUIT");
    assert_eq!(exchange["outcome"], "no_response");
    assert_eq!(exchange["replay_safe"], true);
    assert_eq!(exchange["parse_warnings"], serde_json::json!([]));
    let closed = events
        .iter()
        .find(|value| value["event_type"] == "redis_connection" && value["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], true);

    state
        .recorder()
        .flush_global_dependency_files()
        .await
        .unwrap();
    let semantic = crate::recorder::test_io::read_to_string(
        state.recorder().run_dir.join("global-dependencies.jsonl"),
    )
    .await
    .unwrap();
    let quit: serde_json::Value = semantic
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|value| value["command"] == "QUIT")
        .unwrap();
    assert_eq!(quit["capture"]["semantic_required"], false);
}

#[tokio::test]
async fn partial_request_rejects_abortive_client_close() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state, upstream_addr);

    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$3\r\nke")
        .await
        .unwrap();
    enable_abortive_close(&client);
    drop(client);

    let mut forwarded = Vec::new();
    assert_eq!(
        upstream
            .read_to_end(&mut forwarded)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert_eq!(forwarded, b"*2\r\n$3\r\nGET\r\n$3\r\nke");
    drop(upstream);

    let result = tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn raw_fallback_reports_later_case_activity_on_the_same_connection() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let first_case = test_case("first");
    let first_guard = state.try_reserve_active_case(first_case.clone()).unwrap();
    state
        .activate_case_dependencies(&first_guard)
        .expect("first case dependencies should activate");
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    upstream.write_all(b"+PONG\r\n").await.unwrap();
    let mut unsolicited = [0_u8; 7];
    client.read_exact(&mut unsolicited).await.unwrap();
    assert_eq!(&unsolicited, b"+PONG\r\n");
    drop(first_guard);

    let second_case = test_case("second");
    let second_guard = state.try_reserve_active_case(second_case.clone()).unwrap();
    state
        .activate_case_dependencies(&second_guard)
        .expect("second case dependencies should activate");
    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    client.write_all(request).await.unwrap();
    let mut forwarded = vec![0_u8; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, request);

    client.shutdown().await.unwrap();
    upstream.shutdown().await.unwrap();
    drop(client);
    drop(upstream);
    let result = tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "Redis response arrived without a pending request; switched to raw forwarding"
    );

    let first_errors = case_proxy_errors(&state, &first_case).await;
    let second_errors = case_proxy_errors(&state, &second_case).await;
    assert_eq!(first_errors.len(), 1);
    assert_eq!(second_errors.len(), 1);
    assert_eq!(
        first_errors[0]["connection_id"],
        second_errors[0]["connection_id"]
    );
    assert_eq!(second_errors[0]["protocol"], "redis");
    assert_eq!(
        second_errors[0]["error"],
        "Redis response arrived without a pending request; switched to raw forwarding"
    );
}

fn test_case(name: &str) -> CaseContext {
    CaseContext {
        id: Uuid::new_v4(),
        rule_name: name.to_string(),
        uri_group: None,
    }
}

async fn case_proxy_errors(state: &AppState, case: &CaseContext) -> Vec<serde_json::Value> {
    let dir = state.recorder().case_staging_dir(case);
    state
        .recorder()
        .flush_case_dependency_files(&dir)
        .await
        .unwrap();
    let raw = crate::recorder::test_io::read_to_string(dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    raw.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event_type"] == "proxy_error")
        .collect()
}

async fn test_state(access_policy: RecordingAccessPolicy) -> (AppState, TempDir) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = access_policy;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    (AppState::new(config).await.unwrap(), temp)
}

async fn snapshot_test_state() -> (AppState, TempDir) {
    redis_process_test_state(Some(1_000)).await
}

async fn redis_process_test_state(initial_load_timeout_ms: Option<u64>) -> (AppState, TempDir) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config
        .process_dependency_tasks
        .insert("snapshot-get".into(), "cache_refresh".into());
    config.recording.output_dir = temp.path().join("recordings");
    config.http_gateway.enabled = true;
    config.http_gateway.ready.enabled = true;
    config
        .process_owned_dependencies
        .push(BackgroundDependencyRuleConfig::Redis {
            key_sequence: Vec::new(),
            script: None,
            trigger_source: None,
            key_templates: Vec::new(),
            arguments: Vec::new(),
            name: "snapshot-get".to_string(),
            ports: vec![6379],
            command: "GET".to_string(),
            keys: vec!["key".to_string()],
            key_patterns: Vec::new(),
            key_prefix: String::new(),
            key_suffix: String::new(),
            initial_load_timeout_ms,
            fields: Vec::new(),
            source_revision: "abcdef1".to_string(),
            source_evidence: "Cache.java:42".to_string(),
        });
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    (AppState::new(config).await.unwrap(), temp)
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(TcpStream::connect(addr));
    let (server, _) = listener.accept().await.unwrap();
    (client.await.unwrap().unwrap(), server)
}

fn spawn_handler(
    proxy_client: TcpStream,
    proxy_upstream: TcpStream,
    state: AppState,
    upstream_addr: std::net::SocketAddr,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(handle_connected(
        proxy_client,
        proxy_upstream,
        state,
        ConnectionContext {
            client_addr: None,
            target_host: "redis.test".to_string(),
            target_port: 6379,
            target_addr: "redis.test:6379".to_string(),
            upstream_addr: upstream_addr.to_string(),
        },
    ))
}

fn enable_abortive_close(stream: &TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        )
    };
    assert_eq!(result, 0, "failed to enable abortive close");
}

#[path = "tests/pubsub_rpc.rs"]
mod pubsub_rpc;

#[path = "tests/subscription_evidence.rs"]
mod subscription_evidence;
