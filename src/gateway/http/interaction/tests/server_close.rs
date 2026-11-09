//! Source-owned closure preserves pending business and recorded heartbeat input.

use super::*;
use crate::interaction::model::EndReason;
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::CloseFrame};

const CONNECT: &str = "40/local-executor,{}";
const REGISTER: &str = "42/local-executor,409[\"device:register\",{}]";
const REGISTERED: &str = "43/local-executor,409[{\"success\":true}]";
const SYNC: &str = "42/local-executor,2[\"device:sync_capabilities\",{}]";
const HEARTBEAT: &str = "42/local-executor,[\"device:heartbeat\",{}]";
const PULL: &str = "42/local-executor,216[\"runtime.tasks.pull\",{}]";
const PULLED: &str = "43/local-executor,216[{\"success\":true}]";

async fn text(socket: &mut WebSocketStream<tokio::net::TcpStream>) -> String {
    timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap()
        .to_string()
}

async fn executor_peer(
    stream: tokio::net::TcpStream,
    sid: &str,
    ping_payload: &str,
    reply_first: bool,
) {
    let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(
            format!(
                "0{{\"sid\":\"{sid}\",\"upgrades\":[],\"pingInterval\":50,\"pingTimeout\":120}}"
            )
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(text(&mut socket).await, CONNECT);
    socket
        .send(Message::Text(
            format!("40/local-executor,{{\"sid\":\"{sid}-namespace\"}}").into(),
        ))
        .await
        .unwrap();
    assert_eq!(text(&mut socket).await, REGISTER);
    socket.send(Message::Text(REGISTERED.into())).await.unwrap();
    socket.send(Message::Text(SYNC.into())).await.unwrap();
    assert_eq!(text(&mut socket).await, HEARTBEAT);
    assert_eq!(text(&mut socket).await, PULL);
    socket.send(Message::Text(PULLED.into())).await.unwrap();
    socket
        .send(Message::Text(format!("2{ping_payload}").into()))
        .await
        .unwrap();
    if reply_first {
        assert_eq!(text(&mut socket).await, format!("3{ping_payload}"));
        socket
            .send(Message::Text(format!("2{ping_payload}-unanswered").into()))
            .await
            .unwrap();
    }
    assert!(
        timeout(Duration::from_millis(120), socket.next())
            .await
            .is_err(),
        "the peer must observe no PONG, invented business ACK or engine close"
    );
    socket
        .close(Some(CloseFrame {
            code: 1000.into(),
            reason: "".into(),
        }))
        .await
        .unwrap();
}

#[tokio::test]
async fn source_close_with_pending_records_replays_and_preserves_the_source_service() {
    for reply_first in [true, false] {
        timeout(Duration::from_secs(25), record_replay_and_next(reply_first))
            .await
            .unwrap();
    }
}

async fn record_replay_and_next(reply_first: bool) {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    settings.http_gateway.request_timeout_ms = 3_000;
    settings.http_gateway.interaction.request_timeout_ms = 3_000;
    settings.http_gateway.interaction.max_duration_ms = 4_000;
    settings.http_gateway.interaction.business_idle_ms = 600;
    settings.http_gateway.interaction.completion.clear();
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        executor_peer(stream, "source", "source-first", reply_first).await;
        loop {
            let (mut stream, _) = upstream.accept().await.unwrap();
            read_head(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnext").await.unwrap();
        }
    });
    let (address, recording) = gateway(state.clone()).await;
    let (mut client, _) = tokio_tungstenite::connect_async(format!(
        "ws://{address}/socket.io/?EIO=4&transport=websocket"
    ))
    .await
    .unwrap();
    assert!(
        client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with('0')
    );
    client.send(Message::Text(CONNECT.into())).await.unwrap();
    assert!(
        client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with("40/local-executor,")
    );
    client.send(Message::Text(REGISTER.into())).await.unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        REGISTERED
    );
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        SYNC
    );
    client.send(Message::Text(HEARTBEAT.into())).await.unwrap();
    client.send(Message::Text(PULL.into())).await.unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        PULLED
    );
    let mut ping_count = 0;
    loop {
        match client.next().await.unwrap().unwrap() {
            Message::Text(message) => {
                assert!(message.starts_with('2'));
                ping_count += 1;
                if reply_first && ping_count == 1 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    client
                        .send(Message::Text(format!("3{}", &message[1..]).into()))
                        .await
                        .unwrap();
                }
            }
            Message::Close(frame) => {
                assert!(
                    frame.is_some_and(|frame| frame.code == 1000.into() && frame.reason.is_empty())
                );
                break;
            }
            message => panic!("unexpected Source message: {message:?}"),
        }
    }
    assert_eq!(ping_count, if reply_first { 2 } else { 1 });
    assert!(
        !state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_millis(75))
            .await,
        "a Socket.IO server close with pending work must keep dependency admission open"
    );
    let case = published_within(&state, Duration::from_secs(18)).await;
    let input: Value = serde_json::from_slice(
        &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
    )
    .unwrap();
    assert!(input["interaction"]["socket_io_heartbeat"].is_object());
    assert_eq!(
        input["interaction"]["socket_io_heartbeat"]["responses"]
            .as_array()
            .unwrap()
            .len(),
        usize::from(reply_first)
    );
    let expected: Value =
        serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
            .unwrap();
    let pending = serde_json::json!([2, 3, 4, (1_u64 << 63) | 1]);
    assert_eq!(expected["interaction"]["end"]["reason"], "server_eof");
    assert_eq!(expected["interaction"]["end"]["clean"], true);
    assert_eq!(expected["interaction"]["end"]["pending"], pending);
    assert_eq!(expected["interaction"]["end"]["close"]["code"], 1000);
    assert_eq!(state.recording_lifecycle_phase(), "running");
    assert!(!*state.inner.interactions.source_stop.borrow());

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (stream, _) = target.accept().await.unwrap();
        executor_peer(stream, "target", "target-first", reply_first).await;
    });
    let actual = replay_case(&case, target_address).await;
    assert_eq!(actual.end.reason, EndReason::ServerEof);
    assert_eq!(actual.end.pending, vec![2, 3, 4, (1_u64 << 63) | 1]);
    assert!(actual.end.clean);
    target.await.unwrap();

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{address}/next"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "next"
    );
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(2))
            .await
    );
    let mut cases = Vec::new();
    find_cases(&state.recorder().run_dir.join("apis"), &mut cases);
    assert_eq!(cases.len(), 2);
    assert_eq!(state.recording_lifecycle_phase(), "running");
    assert!(!*state.inner.interactions.source_stop.borrow());
    assert!(!source.is_finished());
    source.abort();
    recording.abort();
}

#[tokio::test]
async fn socketio_eof_without_a_close_frame_still_fails_capture() {
    timeout(Duration::from_secs(5), async {
        let temp = tempdir().unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap()))
            .await
            .unwrap();
        let source = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket
                .send(Message::Text(
                    "0{\"sid\":\"source\",\"upgrades\":[],\"pingInterval\":50,\"pingTimeout\":120}"
                        .into(),
                ))
                .await
                .unwrap();
            assert_eq!(text(&mut socket).await, CONNECT);
            socket
                .send(Message::Text(
                    "40/local-executor,{\"sid\":\"source-namespace\"}".into(),
                ))
                .await
                .unwrap();
            assert_eq!(text(&mut socket).await, REGISTER);
            socket.send(Message::Text(REGISTERED.into())).await.unwrap();
            socket.get_mut().shutdown().await.unwrap();
        });
        let (address, recording) = gateway(state.clone()).await;
        let (mut client, _) = tokio_tungstenite::connect_async(format!(
            "ws://{address}/socket.io/?EIO=4&transport=websocket"
        ))
        .await
        .unwrap();
        client.next().await.unwrap().unwrap();
        client.send(Message::Text(CONNECT.into())).await.unwrap();
        client.next().await.unwrap().unwrap();
        client.send(Message::Text(REGISTER.into())).await.unwrap();
        while let Some(Ok(message)) = client.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
        source.await.unwrap();
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let report: Value = serde_json::from_slice(
            &std::fs::read(state.recorder().run_dir.join("recording-run.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report["published_cases"], 0);
        assert_eq!(report["failed_cases"], 1);
        assert!(*state.inner.interactions.source_stop.borrow());
        recording.abort();
    })
    .await
    .unwrap();
}

struct PollingPeer {
    address: SocketAddr,
    requests_after_close: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: JoinHandle<()>,
}

async fn polling_exchange(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    uri: &str,
    body: Option<&str>,
) -> String {
    let response = client
        .request(
            Request::builder()
                .method(if body.is_some() { "POST" } else { "GET" })
                .uri(uri)
                .body(Full::new(Bytes::copy_from_slice(
                    body.unwrap_or("").as_bytes(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

impl Drop for PollingPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn polling_peer(sid: &'static str) -> PollingPeer {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::sync::{Mutex, mpsc};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<String>(8);
    let rx = Arc::new(Mutex::new(rx));
    let closed = Arc::new(AtomicBool::new(false));
    let after = Arc::new(AtomicUsize::new(0));
    let requests_after_close = after.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (tx, rx, closed, after) = (tx.clone(), rx.clone(), closed.clone(), after.clone());
            connections.spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                    let (tx, rx, closed, after) = (tx.clone(), rx.clone(), closed.clone(), after.clone());
                    async move {
                        let data = if request.uri().path() == "/next" {
                            "next".to_owned()
                        } else if super::super::query(request.uri(), "sid").is_none() {
                            format!("0{{\"sid\":\"{sid}\",\"upgrades\":[],\"pingInterval\":50,\"pingTimeout\":120}}")
                        } else if request.method() == hyper::Method::GET {
                            if closed.load(Ordering::SeqCst) {
                                after.fetch_add(1, Ordering::SeqCst);
                                return Ok::<_, std::convert::Infallible>(hyper::Response::builder().status(400).body(Full::new(Bytes::from_static(b"session closed"))).unwrap());
                            }
                            let data = rx.lock().await.recv().await.unwrap();
                            if data.split('\u{1e}').any(|packet| packet == "1") {
                                closed.store(true, Ordering::SeqCst);
                            }
                            data
                        } else {
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            match std::str::from_utf8(&bytes).unwrap() {
                                CONNECT => tx.send(format!("40/local-executor,{{\"sid\":\"{sid}-namespace\"}}")).await.unwrap(),
                                REGISTER => tx.send(format!("{REGISTERED}\u{1e}{SYNC}\u{1e}1")).await.unwrap(),
                                input => panic!("unexpected polling input: {input:?}"),
                            }
                            "ok".to_owned()
                        };
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(data))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
            });
        }
    });
    PollingPeer {
        address,
        requests_after_close,
        task,
    }
}

#[tokio::test]
async fn polling_protocol_close_with_pending_records_replays_and_does_not_invent_websocket_close() {
    timeout(Duration::from_secs(25), async {
        let temp = tempdir().unwrap();
        let source = polling_peer("source").await;
        let mut settings = config(temp.path(), source.address);
        settings.http_gateway.interaction.business_idle_ms = 600;
        settings.http_gateway.interaction.completion.clear();
        let state = AppState::new(settings).await.unwrap();
        let (address, recording) = gateway(state.clone()).await;
        let client = Client::builder(TokioExecutor::new()).build_http();
        let initial = format!("http://{address}/socket.io/?EIO=4&transport=polling");
        assert!(
            polling_exchange(&client, &initial, None)
                .await
                .starts_with('0')
        );
        let session = format!("{initial}&sid=source");
        assert_eq!(
            polling_exchange(&client, &session, Some(CONNECT)).await,
            "ok"
        );
        assert!(
            polling_exchange(&client, &session, None)
                .await
                .starts_with("40/local-executor,")
        );
        assert_eq!(
            polling_exchange(&client, &session, Some(REGISTER)).await,
            "ok"
        );
        assert_eq!(
            polling_exchange(&client, &session, None).await,
            format!("{REGISTERED}\u{1e}{SYNC}\u{1e}1")
        );
        let case = published_within(&state, Duration::from_secs(18)).await;
        let expected: Value =
            serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
                .unwrap();
        assert_eq!(expected["interaction"]["end"]["reason"], "server_eof");
        assert_eq!(expected["interaction"]["end"]["clean"], true);
        assert_eq!(
            expected["interaction"]["end"]["pending"],
            serde_json::json!([2, (1_u64 << 63) | 1])
        );
        assert!(expected["interaction"]["end"].get("close").is_none());
        assert!(!*state.inner.interactions.source_stop.borrow());
        let target = polling_peer("target").await;
        let actual = replay_case(&case, target.address).await;
        assert!(actual.end.clean);
        assert_eq!(actual.end.pending, vec![2, (1_u64 << 63) | 1]);
        assert!(actual.end.close.is_none());
        assert_eq!(
            target
                .requests_after_close
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            polling_exchange(&client, &format!("http://{address}/next"), None).await,
            "next"
        );
        assert!(
            state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        assert_eq!(state.recording_lifecycle_phase(), "running");
        assert!(!*state.inner.interactions.source_stop.borrow());
        recording.abort();
    })
    .await
    .unwrap();
}
