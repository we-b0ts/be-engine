use super::*;
use crate::interaction::{
    model::{InputTranscript, Protocol},
    policy::{CompletionRule, EventCompletion, InteractionPolicy},
};
use futures_util::{SinkExt as _, StreamExt as _};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn policy() -> InteractionPolicy {
    InteractionPolicy {
        business_idle_ms: 100,
        max_duration_ms: 2_000,
        cleanup_timeout_ms: 200,
        request_timeout_ms: 1_000,
        input_gap_ms: 1,
        completion: vec![EventCompletion {
            namespace: "/".into(),
            event: "ask".into(),
            completion: CompletionRule::Ack,
        }],
        ..InteractionPolicy::default()
    }
}

fn program() -> InputTranscript {
    let mut transcript = InputTranscript::new(Protocol::SocketIo, policy());
    transcript.actions = vec![
        InputAction {
            sequence: 1,
            offset_ms: 0,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text("40"),
            },
        },
        InputAction {
            sequence: 2,
            offset_ms: 5,
            after: vec![1],
            compressible_gap: true,
            gap_start_ms: Some(1),
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text("421[\"ask\",{\"value\":7}]"),
            },
        },
    ];
    transcript
}

fn open() -> &'static str {
    "0{\"sid\":\"actual-target-sid\",\"upgrades\":[],\"pingInterval\":1000,\"pingTimeout\":1000,\"maxPayload\":1048576}"
}

#[tokio::test]
async fn websocket_replay_drives_live_target_and_ignores_only_protocol_heartbeat_for_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text("40{\"sid\":\"actual-namespace\"}".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "421[\"ask\",{\"value\":7}]"
        );
        socket
            .send(Message::Text("431[\"ok\"]".into()))
            .await
            .unwrap();
        socket.send(Message::Text("2live".into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "3live"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &program(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(response.status, hyper::StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.observation.end.reason, EndReason::BusinessIdle);
    assert!(response.observation.end.clean);
    assert!(
        response
            .observation
            .events
            .iter()
            .any(|event| event.heartbeat && event.message.data == "2live")
    );
    assert!(
        response
            .observation
            .events
            .iter()
            .any(|event| event.message.data == "431[\"ok\"]")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn polling_replay_uses_target_sid_and_pumps_get_while_posting_client_inputs() {
    use http_body_util::BodyExt as _;
    use hyper::{Response, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;
    use tokio::sync::{Mutex, mpsc};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<String>(16);
    let rx = Arc::new(Mutex::new(rx));
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            let rx = rx.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let tx = tx.clone();
                    let rx = rx.clone();
                    async move {
                        let uri = request.uri().to_string();
                        let data = if !uri.contains("sid=") {
                            open().to_owned()
                        } else {
                            assert!(
                                uri.contains("sid=actual-target-sid"),
                                "must bind the live Target SID: {uri}"
                            );
                            if request.method() == hyper::Method::GET {
                                rx.lock().await.recv().await.unwrap_or_else(|| "1".into())
                            } else {
                                let payload =
                                    request.into_body().collect().await.unwrap().to_bytes();
                                match payload.as_ref() {
                                    b"40" => tx
                                        .send("40{\"sid\":\"actual-namespace\"}".into())
                                        .await
                                        .unwrap(),
                                    b"421[\"ask\",{\"value\":7}]" => {
                                        tx.send("431[\"ok\"]".into()).await.unwrap()
                                    }
                                    b"1" => {
                                        let _ = tx.send("1".into()).await;
                                    }
                                    value => panic!("unexpected polling client payload: {value:?}"),
                                }
                                "ok".into()
                            }
                        };
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            data,
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=polling"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &program(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(response.observation.end.reason, EndReason::BusinessIdle);
    assert!(response.observation.end.clean);
    assert!(
        response
            .observation
            .events
            .iter()
            .any(|event| event.message.data == "431[\"ok\"]")
    );
    server.abort();
}

#[tokio::test]
async fn server_ack_reference_waits_for_live_target_event_and_rebinds_its_generated_id() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text("40{\"sid\":\"target-ns\"}".into()))
            .await
            .unwrap();
        // Source sent its ACK at 5 ms; actual Target event arrives later and uses a new ID.
        tokio::time::sleep(Duration::from_millis(10)).await;
        socket
            .send(Message::Text("42777[\"notice\",{}]".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "43777[\"received\"]"
        );
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
    });
    let mut transcript = program();
    transcript.actions[1].after.clear();
    transcript.actions[1].compressible_gap = false;
    transcript.actions[1].gap_start_ms = None;
    transcript.actions[1].ack_ref = Some(crate::interaction::model::AckReference {
        namespace: "/".into(),
        server_event_ordinal: 1,
    });
    transcript.actions[1].action = InputActionKind::Message {
        message: WireMessage::text("43123[\"received\"]"),
    };
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &transcript,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(response.observation.end.clean);
    server.await.unwrap();
}

#[tokio::test]
async fn generic_websocket_uses_explicit_terminal_without_injecting_engine_io_packets() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "request"
        );
        socket.send(Message::Text("answer".into())).await.unwrap();
        socket.send(Message::Text("done".into())).await.unwrap();
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });
    let mut transcript = InputTranscript::new(
        Protocol::WebSocket,
        InteractionPolicy {
            stream_terminal: Some(crate::interaction::policy::StreamTerminal::Text {
                value: "done".into(),
            }),
            ..policy()
        },
    );
    transcript.actions.push(InputAction {
        sequence: 1,
        offset_ms: 0,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("request"),
        },
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/chat"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &transcript,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert!(response.observation.end.clean);
    assert_eq!(response.observation.events.len(), 2);
    server.await.unwrap();
}

#[tokio::test]
async fn server_websocket_close_code_and_reason_are_observed_independently() {
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text("done".into())).await.unwrap();
        socket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Policy,
                reason: "private auth detail".into(),
            })))
            .await
            .unwrap();
    });
    let transcript = InputTranscript::new(
        Protocol::WebSocket,
        InteractionPolicy {
            stream_terminal: Some(crate::interaction::policy::StreamTerminal::Text {
                value: "done".into(),
            }),
            ..policy()
        },
    );
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/chat"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &transcript,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(
        response.observation.end.close,
        Some(crate::interaction::model::CloseObservation {
            code: Some(1008),
            reason: "private auth detail".into(),
        })
    );
    assert!(response.observation.end.clean);
    server.await.unwrap();
}

#[tokio::test]
async fn client_engine_io_close_is_sent_once_and_ends_with_client_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text("40{\"sid\":\"target-ns\"}".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "421[\"ask\",{\"value\":7}]"
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(40)) => {},
            message = socket.next() => panic!("client closed before the actual Target ACK: {message:?}"),
        }
        socket
            .send(Message::Text("431[\"ok\"]".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "1"
        );
        assert!(
            matches!(socket.next().await.unwrap().unwrap(), Message::Close(_)),
            "must not send a second Engine.IO CLOSE"
        );
    });
    let mut source = Observation::new(Protocol::SocketIo, policy()).unwrap();
    source.output(WireMessage::text(open()), 0).unwrap();
    source.input(WireMessage::text("40"), 0).unwrap();
    source
        .output(WireMessage::text("40{\"sid\":\"source-ns\"}"), 0)
        .unwrap();
    source
        .input(WireMessage::text("421[\"ask\",{\"value\":7}]"), 0)
        .unwrap();
    source.output(WireMessage::text("431[\"ok\"]"), 0).unwrap();
    // Dependency traffic can revoke business-gap compression, while the
    // independently observed completion remains a valid close barrier.
    source.dependency_activity(0);
    let close = source.input(WireMessage::text("1"), 0).unwrap();
    assert_eq!(close.after, vec![2]);
    assert_eq!(close.gap_start_ms, Some(0));
    assert!(!close.compressible_gap);
    let (transcript, source_output) = source.finish(EndReason::ClientClose, 0, true).unwrap();
    assert!(source_output.end.clean);
    assert!(
        transcript
            .actions
            .iter()
            .all(|action| action.offset_ms == 0)
    );
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &transcript,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(response.observation.end.reason, EndReason::ClientClose);
    assert!(response.observation.end.close.is_none());
    assert!(response.observation.end.clean);
    assert!(response.observation.end.offset_ms >= 40);
    server.await.unwrap();
}

#[tokio::test]
async fn server_engine_io_close_preserves_the_following_websocket_close_frame() {
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "40"
        );
        socket
            .send(Message::Text("40{\"sid\":\"target-ns\"}".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "421[\"ask\",{\"value\":7}]"
        );
        socket
            .send(Message::Text("431[\"ok\"]".into()))
            .await
            .unwrap();
        socket.send(Message::Text("1".into())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        socket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "restart".into(),
            })))
            .await
            .unwrap();
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let response = execute(
        &client,
        &origin,
        request,
        &program(),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(response.observation.end.reason, EndReason::ServerEof);
    assert_eq!(
        response.observation.end.close,
        Some(crate::interaction::model::CloseObservation {
            code: Some(1001),
            reason: "restart".into()
        })
    );
    assert!(response.observation.end.clean);
    server.await.unwrap();
}
