use super::*;

#[tokio::test]
async fn finite_process_get_forwards_changing_values_and_records_every_exchange() {
    let (state, _temp) = redis_process_test_state(None).await;
    let (mut client, proxy_client) = tcp_pair().await;
    let (mut upstream, proxy_upstream) = tcp_pair().await;
    let upstream_addr = upstream.peer_addr().unwrap();
    let handler = spawn_handler(proxy_client, proxy_upstream, state.clone(), upstream_addr);
    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    for response in [b"$2\r\nv1\r\n".as_slice(), b"$-1\r\n".as_slice()] {
        client.write_all(request).await.unwrap();
        let mut received = vec![0; request.len()];
        tokio::time::timeout(Duration::from_secs(1), upstream.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, request);
        upstream.write_all(response).await.unwrap();
        let mut received = vec![0; response.len()];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, response);
    }
    client.shutdown().await.unwrap();
    drop(client);
    assert_eq!(upstream.read(&mut [0; 1]).await.unwrap(), 0);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(1), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    state.recorder().flush_traffic().await.unwrap();
    state
        .recorder()
        .flush_global_dependency_files()
        .await
        .unwrap();
    let raw = tokio::fs::read_to_string(state.recorder().run_dir.join("global-dependencies.jsonl"))
        .await
        .unwrap();
    let exchanges: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &serde_json::Value| event["event_type"] == "redis_exchange")
        .collect();
    assert_eq!(exchanges.len(), 2);
    for event in &exchanges {
        assert!(event["cache_snapshot_rule"].is_null());
        assert!(event["cache_snapshot_hit"] != true);
        assert_eq!(event["global_dependency_reason"], "background_rule");
    }
    assert_ne!(exchanges[0]["response"], exchanges[1]["response"]);
}
