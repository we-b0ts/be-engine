use super::*;
use crate::dependency::{
    DependencyTermination, TerminationKind, TerminationScope, TerminationSide,
};

const GET: &[u8] = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";

async fn records(state: &AppState) -> Vec<serde_json::Value> {
    state.recorder().flush_traffic().await.unwrap();
    crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn terminated(side: TerminationSide, kind: TerminationKind) -> serde_json::Value {
    serde_json::to_value(DependencyExchangeOutcome::Terminated(
        DependencyTermination {
            side,
            kind,
            scope: if kind == TerminationKind::Eof {
                TerminationScope::WriteHalf
            } else {
                TerminationScope::Connection
            },
        },
    ))
    .unwrap()
}

async fn finish(handler: tokio::task::JoinHandle<Result<()>>) {
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn server_eof_reaches_client_before_client_close_and_uses_observation_clock() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    let started = Instant::now();
    client.write_all(GET).await.unwrap();
    upstream.read_exact(&mut vec![0; GET.len()]).await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut probe))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let eof_received_ms = started.elapsed().as_millis() as u64;
    // Keep the request direction open after the response FIN. Recording duration
    // must not include the later connection-owner cleanup.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!handler.is_finished());
    client.shutdown().await.unwrap();
    assert_eq!(upstream.read(&mut probe).await.unwrap(), 0);
    drop(client);
    drop(upstream);
    finish(handler).await;
    let records = records(&state).await;
    let exchange = records
        .iter()
        .find(|r| r["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(
        exchange["outcome"],
        terminated(TerminationSide::Server, TerminationKind::Eof)
    );
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() <= eof_received_ms + 10);
}

#[tokio::test]
async fn client_write_half_close_still_receives_complete_response() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    client.write_all(GET).await.unwrap();
    upstream.read_exact(&mut vec![0; GET.len()]).await.unwrap();
    client.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(upstream.read(&mut probe).await.unwrap(), 0);
    upstream.write_all(b"$5\r\nvalue\r\n").await.unwrap();
    let mut response = [0; 11];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"$5\r\nvalue\r\n");
    upstream.shutdown().await.unwrap();
    drop(upstream);
    drop(client);
    finish(handler).await;
    let records = records(&state).await;
    let exchange = records
        .iter()
        .find(|r| r["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["outcome"], "response");
    assert_eq!(exchange["replay_safe"], true);
}

#[tokio::test]
async fn partial_response_eof_preserves_pipeline_order_and_prefix() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    client.write_all(&[GET, GET, GET].concat()).await.unwrap();
    upstream
        .read_exact(&mut vec![0; GET.len() * 3])
        .await
        .unwrap();
    let response = b"$1\r\na\r\n$5\r\npar";
    upstream.write_all(response).await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, response);
    client.shutdown().await.unwrap();
    drop(client);
    drop(upstream);
    finish(handler).await;
    let records = records(&state).await;
    let exchanges: Vec<_> = records
        .iter()
        .filter(|r| r["event_type"] == "redis_exchange")
        .collect();
    assert_eq!(exchanges.len(), 3);
    assert_eq!(exchanges[0]["outcome"], "response");
    assert_eq!(
        exchanges[1]["outcome"],
        terminated(TerminationSide::Server, TerminationKind::Eof)
    );
    assert_eq!(exchanges[1]["response"]["original_len"], 7);
    assert_eq!(exchanges[1]["replay_safe"], true);
    assert_eq!(
        exchanges[2]["outcome"],
        terminated(TerminationSide::Server, TerminationKind::Eof)
    );
    assert_eq!(exchanges[2]["response"]["original_len"], 0);
    assert_eq!(exchanges[2]["replay_safe"], true);
}

#[tokio::test]
async fn server_reset_is_forwarded_as_reset_and_recorded_as_complete_failure() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    client.write_all(GET).await.unwrap();
    upstream.read_exact(&mut vec![0; GET.len()]).await.unwrap();
    enable_abortive_close(&upstream);
    drop(upstream);
    let error = tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    drop(client);
    finish(handler).await;
    let records = records(&state).await;
    let exchange = records
        .iter()
        .find(|r| r["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(
        exchange["outcome"],
        terminated(TerminationSide::Server, TerminationKind::Reset)
    );
    assert_eq!(exchange["replay_safe"], true);
}

#[tokio::test]
async fn client_reset_is_forwarded_upstream_and_retains_client_ownership() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    client.write_all(GET).await.unwrap();
    upstream.read_exact(&mut vec![0; GET.len()]).await.unwrap();
    enable_abortive_close(&client);
    drop(client);
    let error = tokio::time::timeout(Duration::from_secs(1), upstream.read(&mut [0]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    drop(upstream);
    finish(handler).await;
    let records = records(&state).await;
    let exchange = records
        .iter()
        .find(|r| r["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(
        exchange["outcome"],
        terminated(TerminationSide::Client, TerminationKind::Reset)
    );
    assert_eq!(exchange["replay_safe"], true);
}

#[tokio::test]
async fn recorder_cleanup_cannot_become_a_replayable_peer_failure() {
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    client.write_all(GET).await.unwrap();
    upstream.read_exact(&mut vec![0; GET.len()]).await.unwrap();
    state.dependency_connections().reset_open_connections();
    finish(handler).await;
    let records = records(&state).await;
    let exchange = records
        .iter()
        .find(|r| r["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["replay_safe"], false);
    assert_eq!(exchange["outcome"], "response");
}

#[tokio::test]
async fn client_fin_then_later_partial_response_remains_transparent_but_is_not_claimed_replayable()
{
    let (state, _temp) = test_state(RecordingAccessPolicy::Unrestricted).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    client.write_all(GET).await.unwrap();
    upstream.read_exact(&mut vec![0; GET.len()]).await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(upstream.read(&mut [0]).await.unwrap(), 0);
    upstream.write_all(b"$5\r\npar").await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"$5\r\npar");
    drop(upstream);
    drop(client);
    finish(handler).await;
    let records = records(&state).await;
    let exchange = records
        .iter()
        .find(|r| r["event_type"] == "redis_exchange")
        .unwrap();
    assert_eq!(exchange["response"]["original_len"], 7);
    assert_eq!(
        exchange["outcome"],
        terminated(TerminationSide::Client, TerminationKind::Eof)
    );
    assert_eq!(exchange["replay_safe"], false);
    assert!(
        exchange["parse_warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("delivery timing"))
    );
    let closed = records
        .iter()
        .find(|r| r["event_type"] == "redis_connection" && r["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], false);
}
