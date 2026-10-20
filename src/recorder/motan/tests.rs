use std::net::Ipv4Addr;
use std::time::Duration;

use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::AppConfig;

#[tokio::test]
async fn records_successful_exchange_through_the_tcp_proxy() {
    let (state, _temp) = test_state().await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = request_frame(
        42,
        &[
            "cn.sina.api.data.service.SinaUserService",
            "getUser",
            "long",
        ],
    );
    client.write_all(&request).await.unwrap();
    let mut forwarded = vec![0_u8; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    assert_eq!(forwarded, request);

    tokio::time::sleep(Duration::from_millis(20)).await;
    let response = response_frame(42, b"recorded-response");
    upstream.write_all(&response).await.unwrap();
    let mut delivered = vec![0_u8; response.len()];
    client.read_exact(&mut delivered).await.unwrap();
    assert_eq!(delivered, response);

    drop(client);
    let mut eof = [0_u8; 1];
    assert_eq!(upstream.read(&mut eof).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let events = traffic_events(&state).await;
    let exchange = event(&events, "motan_exchange");
    assert_eq!(
        exchange["command"],
        "cn.sina.api.data.service.SinaUserService#getUser"
    );
    assert_eq!(exchange["outcome"], "response");
    assert_eq!(exchange["response_status"], "value");
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 20);
    let closed = events
        .iter()
        .find(|value| value["event_type"] == "motan_connection" && value["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], true);
}

#[tokio::test]
async fn records_client_termination_as_a_replayable_timeout() {
    let (state, _temp) = test_state().await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);

    let request = request_frame(7, &["example.CardService", "getCard", "long"]);
    client.write_all(&request).await.unwrap();
    let mut forwarded = vec![0_u8; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
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

    let events = traffic_events(&state).await;
    let exchange = event(&events, "motan_exchange");
    assert_eq!(exchange["outcome"]["terminated"]["side"], "client");
    assert_eq!(exchange["response"]["original_len"], 0);
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 30);
}

#[tokio::test]
async fn records_server_eof_before_the_client_closes() {
    let (state, _temp) = test_state().await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    let request = request_frame(7, &["example.CardService", "getCard", "long"]);
    client.write_all(&request).await.unwrap();
    let mut forwarded = vec![0; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    upstream.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), client.read(&mut probe))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let events = traffic_events(&state).await;
    let exchange = event(&events, "motan_exchange");
    assert_eq!(exchange["outcome"]["terminated"]["side"], "server");
    assert_eq!(exchange["outcome"]["terminated"]["kind"], "eof");
    assert_eq!(exchange["replay_safe"], true);
    assert!(exchange["duration_ms"].as_u64().unwrap() >= 20);
}

#[tokio::test]
async fn forwards_response_after_client_write_half_is_closed() {
    let (state, _temp) = test_state().await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    let request = request_frame(7, &["example.CardService", "getCard", "long"]);
    client.write_all(&request).await.unwrap();
    let mut forwarded = vec![0; request.len()];
    upstream.read_exact(&mut forwarded).await.unwrap();
    client.shutdown().await.unwrap();
    let mut probe = [0];
    assert_eq!(upstream.read(&mut probe).await.unwrap(), 0);
    let response = response_frame(7, b"after-half-close");
    upstream.write_all(&response).await.unwrap();
    let mut delivered = vec![0; response.len()];
    tokio::time::timeout(
        Duration::from_millis(200),
        client.read_exact(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered, response);
    drop(upstream);
    drop(client);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let events = traffic_events(&state).await;
    assert_eq!(event(&events, "motan_exchange")["outcome"], "response");
}

async fn test_state() -> (AppState, TempDir) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
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
            target_host: "vintage-node-10-145-1-107.trp.test".to_string(),
            target_port: 8881,
            target_addr: "vintage-node-10-145-1-107.trp.test:8881".to_string(),
            advertised_ip: "198.19.0.20".parse::<Ipv4Addr>().unwrap(),
            upstream_addr: upstream_addr.to_string(),
        },
    ))
}

async fn traffic_events(state: &AppState) -> Vec<serde_json::Value> {
    state.recorder().flush_traffic().await.unwrap();
    tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn event<'a>(events: &'a [serde_json::Value], event_type: &str) -> &'a serde_json::Value {
    events
        .iter()
        .find(|value| value["event_type"] == event_type)
        .unwrap()
}

fn request_frame(request_id: u64, identity: &[&str]) -> Vec<u8> {
    let mut block = Vec::new();
    for value in identity {
        block.extend_from_slice(&(value.len() as u16).to_be_bytes());
        block.extend_from_slice(value.as_bytes());
    }
    let mut body = vec![0xAC, 0xED, 0x00, 0x05, 0x77, block.len() as u8];
    body.extend_from_slice(&block);
    frame(request_id, true, 0, &body)
}

fn response_frame(request_id: u64, body: &[u8]) -> Vec<u8> {
    frame(request_id, false, 1, body)
}

fn frame(request_id: u64, request: bool, inner_flag: u8, body: &[u8]) -> Vec<u8> {
    let mut inner = vec![0_u8; 16];
    inner[..2].copy_from_slice(&[0xF0, 0xF0]);
    inner[2] = 1;
    inner[3] = inner_flag;
    inner[4..12].copy_from_slice(&request_id.to_be_bytes());
    inner[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
    inner.extend_from_slice(body);

    let mut outer = vec![0_u8; 16];
    outer[..2].copy_from_slice(&[0xF1, 0xF1]);
    outer[3] = u8::from(!request);
    outer[4..12].copy_from_slice(&request_id.to_be_bytes());
    outer[12..16].copy_from_slice(&(inner.len() as u32).to_be_bytes());
    outer.extend_from_slice(&inner);
    outer
}

mod termination;
