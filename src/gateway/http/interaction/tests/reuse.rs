//! Ordinary interaction completion preserves the Source and the shared dependency window.

use super::*;
use base64::Engine as _;
use tokio::net::TcpStream;

async fn redis_capture(state: AppState) -> (SocketAddr, JoinHandle<()>, JoinHandle<()>) {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let recorder = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recorder_address = recorder.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for turn in 1..=2 {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let expected = format!("*2\r\n$3\r\nGET\r\n$6\r\nlate-{turn}\r\n");
            let mut request = vec![0; expected.len()];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected.as_bytes());
            // The exchange starts inside the 100ms window and finishes after it.
            tokio::time::sleep(Duration::from_millis(140)).await;
            socket.write_all(b"$2\r\nok\r\n").await.unwrap();
        }
    });
    let capture = tokio::spawn(async move {
        for _ in 0..2 {
            let (client, client_address) = recorder.accept().await.unwrap();
            let upstream = TcpStream::connect(upstream_address).await.unwrap();
            crate::recorder::redis::handle_connected(
                client,
                upstream,
                state.clone(),
                crate::recorder::redis::ConnectionContext {
                    client_addr: Some(client_address.to_string()),
                    target_host: "redis.test".into(),
                    target_port: 6379,
                    target_addr: "redis.test:6379".into(),
                    upstream_addr: upstream_address.to_string(),
                },
            )
            .await
            .unwrap();
        }
    });
    (recorder_address, server, capture)
}

async fn late_dependency(address: SocketAddr, turn: usize) {
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(format!("*2\r\n$3\r\nGET\r\n$6\r\nlate-{turn}\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = [0; 8];
    socket.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"$2\r\nok\r\n");
}

async fn source_connection(stream: TcpStream, protocol: Protocol, turn: usize) {
    if protocol == Protocol::Sse {
        let mut stream = stream;
        read_head(&mut stream).await;
        let body = format!("data: turn-{turn}\n\n");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    } else {
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(format!("0{{\"sid\":\"session-{turn}\",\"upgrades\":[],\"pingInterval\":1000,\"pingTimeout\":1000}}").into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("40".into())
        );
        socket.send(Message::Text("40{}".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text(format!("421[\"ask\",{turn}]").into())
        );
        socket
            .send(Message::Text(format!("431[{turn}]").into()))
            .await
            .unwrap();
        match socket.next().await {
            Some(Ok(Message::Text(text))) if text == "1" => {}
            Some(Ok(Message::Close(_))) => {}
            other => panic!("unexpected interaction cleanup: {other:?}"),
        }
        let _ = socket.close(None).await;
    }
}

async fn client_interaction(address: SocketAddr, protocol: Protocol, turn: usize) {
    if protocol == Protocol::Sse {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{address}/events"))
                    .header("accept", "text/event-stream")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let actual = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(actual.as_ref(), format!("data: turn-{turn}\n\n").as_bytes());
    } else {
        let (mut socket, _) = tokio_tungstenite::connect_async(format!(
            "ws://{address}/socket.io/?EIO=4&transport=websocket"
        ))
        .await
        .unwrap();
        assert!(
            socket
                .next()
                .await
                .unwrap()
                .unwrap()
                .to_text()
                .unwrap()
                .starts_with('0')
        );
        socket.send(Message::Text("40".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("40{}".into())
        );
        socket
            .send(Message::Text(format!("421[\"ask\",{turn}]").into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text(format!("431[{turn}]").into())
        );
        assert!(matches!(socket.next().await, Some(Ok(Message::Close(_)))));
    }
}

async fn consecutive_cases(protocol: Protocol) {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new(config(temp.path(), listener.local_addr().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        state
            .config()
            .recording
            .case_dependency_post_response_window_ms,
        100
    );
    let (dependency, server, capture) = redis_capture(state.clone()).await;
    let source = tokio::spawn(async move {
        for turn in 1..=2 {
            let (stream, _) = listener.accept().await.unwrap();
            source_connection(stream, protocol, turn).await;
            late_dependency(dependency, turn).await;
        }
        // The Source service stays alive after both connection-scoped cases.
        std::future::pending::<()>().await;
    });
    let (address, gateway) = gateway(state.clone()).await;
    let mut seen = std::collections::BTreeSet::new();
    timeout(Duration::from_secs(5), async {
        for turn in 1..=2 {
            client_interaction(address, protocol, turn).await;
            assert!(
                state
                    .inner
                    .active_cases
                    .wait_for_no_active_case(Duration::from_secs(2))
                    .await
            );
            state.recorder().flush_traffic().await.unwrap();
            assert_eq!(state.recording_lifecycle_phase(), "running");
            assert!(!*state.inner.interactions.source_stop.borrow());
            assert!(
                !source.is_finished(),
                "case completion must preserve Source"
            );
            let mut cases = Vec::new();
            find_cases(&state.recorder().run_dir.join("apis"), &mut cases);
            assert_eq!(cases.len(), turn);
            let case = cases.into_iter().find(|case| !seen.contains(case)).unwrap();
            let dependencies = std::fs::read_to_string(case.join("dependencies.jsonl")).unwrap();
            let exchanges: Vec<Value> = dependencies
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter(|event| event["event_type"] == "redis_exchange")
                .collect();
            assert_eq!(exchanges.len(), 1);
            assert_eq!(exchanges[0]["event_type"], "redis_exchange");
            let key = base64::engine::general_purpose::STANDARD
                .decode(exchanges[0]["args"][0]["data"].as_str().unwrap())
                .unwrap();
            assert_eq!(key, format!("late-{turn}").as_bytes());
            assert_eq!(exchanges[0]["case_dependency_matched_by"], "active_window");
            seen.insert(case);
        }
        server.await.unwrap();
        capture.await.unwrap();
    })
    .await
    .expect("consecutive cases must finish while the same Source remains alive");
    source.abort();
    gateway.abort();
}

#[tokio::test]
async fn consecutive_sse_cases_reuse_source_and_keep_late_dependencies_in_their_case() {
    consecutive_cases(Protocol::Sse).await;
}

#[tokio::test]
async fn consecutive_socketio_cases_reuse_source_and_keep_late_dependencies_in_their_case() {
    consecutive_cases(Protocol::SocketIo).await;
}
