//! Ordinary interaction completion preserves the Source and the shared dependency window.

use super::*;
use base64::Engine as _;
use tokio::net::TcpStream;

async fn redis_capture(
    state: AppState,
) -> (
    SocketAddr,
    JoinHandle<()>,
    JoinHandle<()>,
    std::sync::Arc<tokio::sync::Notify>,
) {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let recorder = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recorder_address = recorder.local_addr().unwrap();
    let observed = std::sync::Arc::new(tokio::sync::Notify::new());
    let request_observed = observed.clone();
    let server = tokio::spawn(async move {
        for turn in 1..=2 {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let expected = format!("*2\r\n$3\r\nGET\r\n$6\r\nlate-{turn}\r\n");
            let mut request = vec![0; expected.len()];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected.as_bytes());
            request_observed.notify_one();
            // The real request is admitted before the primary closes; its
            // delayed response exercises ownership across that closure.
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
    (recorder_address, server, capture, observed)
}

async fn late_dependency(address: SocketAddr, turn: usize) {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(format!("*2\r\n$3\r\nGET\r\n$6\r\nlate-{turn}\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = [0; 8];
    socket.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"$2\r\nok\r\n");
}

async fn source_connection(
    stream: TcpStream,
    protocol: Protocol,
    turn: usize,
    dependency: SocketAddr,
    observed: std::sync::Arc<tokio::sync::Notify>,
) {
    if protocol == Protocol::Sse {
        let mut stream = stream;
        read_head(&mut stream).await;
        let body = format!("data: turn-{turn}\n\n");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let pending = tokio::spawn(late_dependency(dependency, turn));
        observed.notified().await;
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        drop(stream);
        pending.await.unwrap();
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
        let pending = tokio::spawn(late_dependency(dependency, turn));
        observed.notified().await;
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
        pending.await.unwrap();
    }
}

// Tungstenite fixes the callback error type to an unboxed HTTP response.
#[allow(clippy::result_large_err)]
fn asgi_headers(
    _: &tokio_tungstenite::tungstenite::handshake::server::Request,
    mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::server::Response,
    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
> {
    response
        .headers_mut()
        .insert("server", "uvicorn".parse().unwrap());
    Ok(response)
}

/// Like an ASGI WebSocket stack, the protocol reader can echo WS CLOSE while
/// the application is still awaiting namespace teardown. Only application-side
/// Engine.IO closure after the late resource call proves this operation ended.
async fn source_with_automatic_protocol_close(
    stream: TcpStream,
    turn: usize,
    dependency: SocketAddr,
    application_closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let socket = tokio_tungstenite::accept_hdr_async(stream, asgi_headers)
        .await
        .unwrap();
    let (writer, mut reader) = socket.split();
    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let protocol_writer = writer.clone();
    let (frames, mut input) = tokio::sync::mpsc::channel(8);
    let protocol = tokio::spawn(async move {
        while let Some(Ok(message)) = reader.next().await {
            if let Message::Close(frame) = message {
                let _ = protocol_writer
                    .lock()
                    .await
                    .send(Message::Close(frame))
                    .await;
                break;
            }
            if frames.send(message).await.is_err() {
                break;
            }
        }
    });
    writer.lock().await.send(Message::Text(format!("0{{\"sid\":\"session-{turn}\",\"upgrades\":[],\"pingInterval\":1000,\"pingTimeout\":1000}}").into())).await.unwrap();
    assert_eq!(input.recv().await.unwrap(), Message::Text("40".into()));
    writer
        .lock()
        .await
        .send(Message::Text("40{}".into()))
        .await
        .unwrap();
    assert_eq!(
        input.recv().await.unwrap(),
        Message::Text(format!("421[\"ask\",{turn}]").into())
    );
    writer
        .lock()
        .await
        .send(Message::Text(format!("431[{turn}]").into()))
        .await
        .unwrap();
    assert_eq!(input.recv().await.unwrap(), Message::Text("1".into()));
    // No resource I/O exists at close; the call starts beyond the100ms window.
    tokio::time::sleep(Duration::from_millis(180)).await;
    late_dependency(dependency, turn).await;
    // Python Engine.IO marks the application SID closed but can leave its
    // writer awaiting the client's WS close rather than initiating one.
    application_closed.store(true, std::sync::atomic::Ordering::SeqCst);
    protocol.await.unwrap();
}

async fn asgi_source(listener: TcpListener, dependency: SocketAddr, invalid_after_close: bool) {
    let sessions = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::<
        String,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    >::new()));
    let turns = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let sessions = sessions.clone();
        let turns = turns.clone();
        tokio::spawn(async move {
            let mut bytes = [0; 8192];
            let head = timeout(Duration::from_secs(1), async {
                loop {
                    let count = stream.peek(&mut bytes).await.unwrap();
                    if bytes[..count].windows(4).any(|part| part == b"\r\n\r\n") {
                        break String::from_utf8(bytes[..count].to_vec()).unwrap();
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("upgrade: websocket"))
            {
                let turn = turns.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                sessions
                    .lock()
                    .await
                    .insert(format!("session-{turn}"), closed.clone());
                source_with_automatic_protocol_close(stream, turn, dependency, closed).await;
            } else {
                read_head(&mut stream).await;
                let uri = head
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let url = url::Url::parse(&format!("http://localhost{uri}")).unwrap();
                let sid = url
                    .query_pairs()
                    .find(|(key, _)| key == "sid")
                    .unwrap()
                    .1
                    .into_owned();
                assert!(
                    url.query_pairs()
                        .any(|(key, value)| key == "transport" && value == "websocket")
                );
                let closed = sessions
                    .lock()
                    .await
                    .get(&sid)
                    .unwrap()
                    .load(std::sync::atomic::Ordering::SeqCst);
                let (status, body) = if closed {
                    (
                        "400 Bad Request",
                        serde_json::to_string(&if invalid_after_close {
                            format!("Invalid session {sid}")
                        } else {
                            format!("Session is disconnected {sid}")
                        })
                        .unwrap(),
                    )
                } else {
                    ("200 OK", "6".into())
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
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
        let close = socket.next().await;
        assert!(
            matches!(close, Some(Ok(Message::Close(_)))),
            "recording close: {close:?}"
        );
    }
}

async fn consecutive_cases(protocol: Protocol, after_close: bool) {
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
    let (dependency, server, capture, observed) = redis_capture(state.clone()).await;
    let source = tokio::spawn(async move {
        if after_close {
            asgi_source(listener, dependency, false).await;
            return;
        }
        for turn in 1..=2 {
            let (stream, _) = listener.accept().await.unwrap();
            source_connection(stream, protocol, turn, dependency, observed.clone()).await;
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
    consecutive_cases(Protocol::Sse, false).await;
}

#[tokio::test]
async fn consecutive_socketio_cases_reuse_source_and_keep_late_dependencies_in_their_case() {
    consecutive_cases(Protocol::SocketIo, false).await;
}

#[tokio::test]
async fn consecutive_socketio_cases_capture_resources_started_during_peer_close() {
    consecutive_cases(Protocol::SocketIo, true).await;
}

#[tokio::test]
async fn unknown_asgi_session_does_not_certify_application_close() {
    let temp = tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new(config(temp.path(), listener.local_addr().unwrap()))
        .await
        .unwrap();
    let (dependency, server, capture, _) = redis_capture(state.clone()).await;
    let source = tokio::spawn(asgi_source(listener, dependency, true));
    let (address, gateway) = gateway(state.clone()).await;
    client_interaction(address, Protocol::SocketIo, 1).await;
    let writers = state.capture_dependency_targets();
    let case = writers.cases[0].0.clone();
    drop(writers);
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(3))
            .await
    );
    let failed = state.recorder().case_failed_dir(&case);
    let error: Value = serde_json::from_slice(
        &tokio::fs::read(failed.join("recording-error.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["reason"], "interaction_transport_failed");
    assert!(!state.recorder().case_dir(&case).exists());
    assert!(*state.inner.interactions.source_stop.borrow());
    source.abort();
    server.abort();
    capture.abort();
    gateway.abort();
}
