use super::*;

async fn connected() -> (
    AppState,
    TempDir,
    TcpStream,
    TcpStream,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (state, temp) = test_state().await;
    let (client, proxy_client) = tcp_pair().await;
    let (upstream, proxy_upstream) = tcp_pair().await;
    let handler = spawn_handler(
        proxy_client,
        proxy_upstream,
        state.clone(),
        upstream.peer_addr().unwrap(),
    );
    (state, temp, client, upstream, handler)
}

async fn send_request(client: &mut TcpStream, upstream: &mut TcpStream, id: u64) {
    let request = request_frame(id, &["example.CardService", "getCard", "long"]);
    client.write_all(&request).await.unwrap();
    let mut forwarded = vec![0; request.len()];
    tokio::time::timeout(
        Duration::from_millis(500),
        upstream.read_exact(&mut forwarded),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(forwarded, request);
}

#[tokio::test]
async fn server_fin_keeps_source_write_half_open_and_later_calls_unsafe() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_request(&mut client, &mut upstream, 7).await;
    upstream.shutdown().await.unwrap();
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    send_request(&mut client, &mut upstream, 8).await;
    client.shutdown().await.unwrap();
    assert_eq!(upstream.read(&mut [0]).await.unwrap(), 0);
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let events = traffic_events(&state).await;
    let later = events
        .iter()
        .find(|event| event["event_type"] == "motan_exchange" && event["sequence"] == 2)
        .unwrap();
    assert_eq!(later["replay_safe"], false);
    assert!(later["outcome"].get("terminated").is_none());
    let closed = events
        .iter()
        .find(|event| event["event_type"] == "motan_connection" && event["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], false);
}

#[tokio::test]
async fn residual_response_and_fin_are_forwarded_before_source_timeout() {
    let (state, _temp, mut client, mut upstream, handler) = connected().await;
    send_request(&mut client, &mut upstream, 7).await;
    let response = response_frame(7, b"incomplete");
    let residual = &response[..20];
    upstream.write_all(residual).await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut delivered = Vec::new();
    tokio::time::timeout(
        Duration::from_millis(500),
        client.read_to_end(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delivered, residual);
    // Decoder failure plus server FIN still does not authorize a Source FIN.
    send_request(&mut client, &mut upstream, 8).await;
    drop(client);
    drop(upstream);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let events = traffic_events(&state).await;
    let closed = events
        .iter()
        .find(|event| event["event_type"] == "motan_connection" && event["phase"] == "closed")
        .unwrap();
    assert_eq!(closed["replay_safe"], false);
}

#[tokio::test]
async fn residual_response_reset_is_forwarded_before_source_timeout() {
    let (_state, _temp, mut client, mut upstream, handler) = connected().await;
    send_request(&mut client, &mut upstream, 7).await;
    let response = response_frame(7, b"incomplete");
    upstream.write_all(&response[..20]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    ConnectionControl::new(&upstream).unwrap().reset().unwrap();
    let mut delivered = Vec::new();
    let error = tokio::time::timeout(
        Duration::from_millis(500),
        client.read_to_end(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    drop(client);
    drop(upstream);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}
