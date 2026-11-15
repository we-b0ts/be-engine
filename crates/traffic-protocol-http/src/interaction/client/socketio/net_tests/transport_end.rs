//! Recorded FIN/RST is a physical input, including while business awaits an ACK.
use super::*;
use crate::interaction::model::{ClientTransportEnd, SocketIoHeartbeats};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};

fn ended_program(socket_io: bool, end: ClientTransportEnd) -> InputTranscript {
    let mut input = if socket_io {
        program()
    } else {
        let mut input = InputTranscript::new(
            Protocol::WebSocket,
            InteractionPolicy {
                stream_terminal: Some(crate::interaction::policy::StreamTerminal::Text {
                    value: "done".into(),
                }),
                ..policy()
            },
        );
        input.actions.push(InputAction {
            sequence: 1,
            offset_ms: 0,
            offset_us: None,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text("request"),
            },
        });
        input
    };
    if socket_io {
        input.socket_io_heartbeat = Some(SocketIoHeartbeats::default());
    }
    input.policy.cleanup_timeout_ms = 1_000;
    input.actions.push(InputAction {
        sequence: input.actions.len() as u64 + 1,
        offset_ms: 70,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::TransportEnd { end },
    });
    input
}

fn assert_peer_end(actual: Option<Result<Message, Error>>, end: ClientTransportEnd) {
    match (end, actual) {
        (
            ClientTransportEnd::Eof,
            Some(Err(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake))),
        ) => {}
        (ClientTransportEnd::Reset, Some(Err(Error::Io(error)))) => {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset)
        }
        (_, actual) => {
            panic!("expected physical {end:?}, never Engine.IO/WS CLOSE; got {actual:?}")
        }
    }
}

#[tokio::test]
async fn eof_and_reset_are_real_inputs_with_pending_work_and_no_synthetic_close() {
    for socket_io in [true, false] {
        for end in [ClientTransportEnd::Eof, ClientTransportEnd::Reset] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (entered, observed_end) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                if socket_io {
                    socket.send(Message::Text(open().into())).await.unwrap();
                    assert_eq!(
                        socket.next().await.unwrap().unwrap(),
                        Message::Text("40".into())
                    );
                    socket
                        .send(Message::Text("40{\"sid\":\"live\"}".into()))
                        .await
                        .unwrap();
                }
                let expected = if socket_io {
                    "421[\"ask\",{\"value\":7}]"
                } else {
                    "request"
                };
                assert_eq!(
                    socket.next().await.unwrap().unwrap(),
                    Message::Text(expected.into())
                );
                assert_peer_end(socket.next().await, end);
                if end == ClientTransportEnd::Eof {
                    // Even an actual server WS CLOSE is not a TCP/application
                    // cleanup receipt. Our half-close must not echo it back.
                    socket.get_mut().write_all(&[0x88, 0x00]).await.unwrap();
                }
                entered.send(()).unwrap();
                released.await.unwrap();
                // For FIN, retaining this actual socket proves that flushing
                // the client's half-close cannot substitute for peer cleanup.
                drop(socket);
            });
            let task = tokio::spawn(async move {
                let origin = format!("http://{address}");
                let path = if socket_io {
                    "/socket.io/?EIO=4&transport=websocket"
                } else {
                    "/ws"
                };
                let request = Request::builder()
                    .uri(format!("{origin}{path}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let client = Client::builder(TokioExecutor::new()).build_http();
                execute(
                    &client,
                    &origin,
                    request,
                    &ended_program(socket_io, end),
                    Duration::from_secs(1),
                )
                .await
            });
            tokio::time::timeout(Duration::from_secs(1), observed_end)
                .await
                .unwrap()
                .unwrap();
            if end == ClientTransportEnd::Eof {
                tokio::time::sleep(Duration::from_millis(25)).await;
                assert!(
                    !task.is_finished(),
                    "FIN must retain its reader until actual peer termination"
                );
            }
            release.send(()).unwrap();
            let response = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                response.observation.end.reason,
                EndReason::ClientTransportEnd
            );
            assert!(response.observation.end.clean);
            assert_eq!(
                response.observation.end.pending,
                vec![if socket_io { 2 } else { 1 }]
            );
            assert!(response.observation.end.close.is_none());
            peer.await.unwrap();
        }
    }
}

#[tokio::test]
async fn raw_end_preempts_unaccepted_namespace_without_certifying_unsent_inputs() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Text(open().into())).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("40".into())
        );
        assert_peer_end(socket.next().await, ClientTransportEnd::Eof);
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let input = ended_program(true, ClientTransportEnd::Eof);
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        execute(&client, &origin, request, &input, Duration::from_secs(1)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response.observation.end.reason,
        EndReason::ClientTransportEnd
    );
    assert!(!response.observation.end.clean);
    assert!(response.observation.end.pending.contains(&1));
    peer.await.unwrap();
}

#[tokio::test]
async fn target_ending_before_the_recorded_transport_input_remains_a_failure() {
    for websocket_close in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket.send(Message::Text(open().into())).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                Message::Text("40".into())
            );
            socket
                .send(Message::Text("40{\"sid\":\"live\"}".into()))
                .await
                .unwrap();
            if websocket_close {
                socket.send(Message::Close(None)).await.unwrap();
            }
        });
        let origin = format!("http://{address}");
        let request = Request::builder()
            .uri(format!("{origin}/socket.io/?EIO=4&transport=websocket"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let client = Client::builder(TokioExecutor::new()).build_http();
        let mut input = ended_program(true, ClientTransportEnd::Eof);
        input.actions.remove(1);
        input.actions[1].sequence = 2;
        input.actions[1].offset_ms = 400;
        if let Ok(response) =
            execute(&client, &origin, request, &input, Duration::from_secs(1)).await
        {
            assert_ne!(
                response.observation.end.reason,
                EndReason::ClientTransportEnd
            );
            assert!(!response.observation.end.clean);
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn queued_target_output_is_observed_before_the_real_transport_end() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket
            .send(Message::Text("unrecorded-target-output".into()))
            .await
            .unwrap();
        assert_peer_end(socket.next().await, ClientTransportEnd::Eof);
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/ws"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let input = ended_program(false, ClientTransportEnd::Eof);
    let started = Instant::now();
    let mut transport = Transport::connect(client, &origin, request, 4096, true)
        .await
        .unwrap();
    // Unlike a sleep, this proves that the real reader has already received and
    // queued the message when the independent terminal action is dispatched.
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.queued_observations() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut observed = Observation::new(Protocol::WebSocket, input.policy.clone()).unwrap();
    observed.input(WireMessage::text("request"), 0).unwrap();
    let mut decoder = SocketIoDecoder::new(4096);
    let mut ordinals = BTreeMap::new();
    let mut receipts = native_receipts::Receipts::default();
    let mut failure = None;
    let result = terminate_transport(
        &mut transport,
        &mut TerminalObservation {
            observed: &mut observed,
            server_decoder: &mut decoder,
            native_events: &None,
            server_ordinals: &mut ordinals,
            native_receipts: &mut receipts,
        },
        ClientTransportEnd::Eof,
        started,
        1000,
        &mut failure,
    )
    .await
    .unwrap();
    assert_eq!(result, (EndReason::ClientTransportEnd, true));
    let (_, output) = observed
        .finish(result.0, elapsed_ms(started), result.1)
        .unwrap();
    assert_eq!(output.events.len(), 1);
    assert_eq!(
        output.events[0].message,
        WireMessage::text("unrecorded-target-output")
    );
    assert!(output.end.clean);
    assert_eq!(output.end.pending, vec![1]);
    peer.await.unwrap();
}

#[tokio::test]
async fn queued_target_close_cannot_be_normalized_by_a_later_raw_input() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        socket.send(Message::Close(None)).await.unwrap();
    });
    let origin = format!("http://{address}");
    let request = Request::builder()
        .uri(format!("{origin}/ws"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let mut transport = Transport::connect(client, &origin, request, 4096, true)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.queued_observations() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let error = transport
        .begin_transport_end(ClientTransportEnd::Eof)
        .unwrap_err();
    assert!(error.to_string().contains("Target ended before recorded"));
    assert!(!transport.raw_end_complete());
    peer.await.unwrap();
}
