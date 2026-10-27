//! Large business messages must not prevent later Engine.IO heartbeats.

use super::*;
use crate::interaction::{
    model::{EndReason, InputActionKind, InputTranscript, OutputObservation},
    policy::{CompletionRule, EventCompletion},
};
use brz_http_gateway::{
    AcquireOutcome, AdmissionFuture, AdmissionProvider, AdmissionRegistry, AdmissionTicket,
    Gateway, OriginService, RouteTable, RoutesConfig,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    },
};

const CONNECT: &str = r#"40/chat,{"token":"fixture"}"#;
const CONNECTED: &str = r#"40/chat,{"sid":"chat-session"}"#;
const JOIN: &str = r#"42/chat,0["task:join",{"task_id":123}]"#;
const ACK: &str = r#"43/chat,1[{"ok":true}]"#;

struct RecordingAdmission(Arc<AtomicUsize>);

impl AdmissionProvider for RecordingAdmission {
    fn try_acquire<'a>(&'a self, scope: &'a str) -> AdmissionFuture<'a> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(AcquireOutcome::Acquired(AdmissionTicket::new(
                scope,
                "fixture-ticket",
            )?))
        })
    }
}

#[test]
fn managed_socketio_large_ack_keeps_bidirectional_messages_and_heartbeats() {
    large_message_exchange(false);
}

#[test]
fn external_sdk_socketio_large_fragmented_ack_keeps_messages_and_heartbeats() {
    large_message_exchange(true);
}

fn padded_message(prefix: &str, bytes: usize) -> String {
    let suffix = "\"}]";
    format!(
        "{prefix}{}{suffix}",
        "x".repeat(bytes - prefix.len() - suffix.len())
    )
}

async fn text<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>) -> String {
    socket
        .next()
        .await
        .expect("WebSocket must remain open")
        .unwrap()
        .into_text()
        .unwrap()
        .to_string()
}

async fn attach_external_gateway(fixture: &mut ManagedSocketFixture) -> Arc<AtomicUsize> {
    let origin = fixture.url.parse().unwrap();
    let config: RoutesConfig = serde_json::from_value(serde_json::json!({
        "routes":[{"methods":["GET"],"path":"/socket.io/",
                   "admission":{"provider":"recorder","scope":"all-apis"}}]
    }))
    .unwrap();
    let admissions = Arc::new(AtomicUsize::new(0));
    let mut registry = AdmissionRegistry::new();
    registry
        .register("recorder", RecordingAdmission(admissions.clone()))
        .unwrap();
    let gateway = Gateway::with_admission(
        RouteTable::compile(config).unwrap(),
        OriginService::new(&origin).unwrap(),
        &origin,
        registry,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    fixture.url = format!("http://{}", listener.local_addr().unwrap());
    fixture.tasks.push(tokio::spawn(async move {
        brz_http_gateway::serve(
            listener,
            gateway,
            std::future::pending::<()>(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    }));
    admissions
}

fn large_message_exchange(external_sdk: bool) {
    runtime().block_on(async {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture =
            ManagedSocketFixture::with_interaction(source.local_addr().unwrap(), |policy| {
                policy.business_idle_ms = 500;
                policy.completion = vec![EventCompletion {
                    namespace: "/chat".into(),
                    event: "task:join".into(),
                    completion: CompletionRule::Ack,
                }];
            })
            .await;
        let admissions = if external_sdk {
            Some(attach_external_gateway(&mut fixture).await)
        } else {
            None
        };
        // Match the production ACK length and exceed the default 128 KiB
        // tungstenite write buffer in both directions.
        let large_ack = padded_message(r#"43/chat,0[{"ok":true,"history":""#, 176_813);
        let large_input = padded_message(
            r#"42/chat,1["task:join",{"task_id":123,"history":""#,
            196_613,
        );
        let source_ack = large_ack.clone();
        let source_input = large_input.clone();
        let (exchanged, observed) = tokio::sync::oneshot::channel();
        fixture.tasks.push(tokio::spawn(async move {
            let (stream, _) = source.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(stream, BodylessHandshake)
                .await
                .unwrap();
            socket.send(Message::Text(OPEN.into())).await.unwrap();
            assert_eq!(text(&mut socket).await, CONNECT);
            socket.send(Message::Text(CONNECTED.into())).await.unwrap();
            assert_eq!(text(&mut socket).await, JOIN);
            if external_sdk {
                for (bytes, opcode, last) in [
                    (&source_ack.as_bytes()[..65_536], Data::Text, false),
                    (&source_ack.as_bytes()[65_536..], Data::Continue, true),
                ] {
                    socket
                        .send(Message::Frame(Frame::message(
                            Bytes::copy_from_slice(bytes),
                            OpCode::Data(opcode),
                            last,
                        )))
                        .await
                        .unwrap();
                }
            } else {
                socket.send(Message::Text(source_ack.into())).await.unwrap();
            }
            socket.send(Message::Text("2".into())).await.unwrap();
            assert_eq!(text(&mut socket).await, "3");
            assert_eq!(text(&mut socket).await, source_input);
            socket.send(Message::Text(ACK.into())).await.unwrap();
            socket.send(Message::Text("2".into())).await.unwrap();
            assert_eq!(text(&mut socket).await, "3");
            exchanged.send(()).unwrap();
            while let Some(message) = socket.next().await {
                if matches!(message.unwrap(), Message::Close(_)) {
                    socket.flush().await.ok();
                    break;
                }
            }
            let (mut stream, _) = source.accept().await.unwrap();
            assert!(
                read_request(&mut stream)
                    .await
                    .starts_with("GET /api/next ")
            );
            send_http_response(&mut stream, "next").await;
        }));
        tokio::time::timeout(Duration::from_secs(8), async {
            let url = format!(
                "{}/socket.io/?EIO=4&transport=websocket",
                fixture.url.replacen("http://", "ws://", 1)
            );
            let (mut client, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            assert_eq!(text(&mut client).await, OPEN);
            client.send(Message::Text(CONNECT.into())).await.unwrap();
            assert_eq!(text(&mut client).await, CONNECTED);
            client.send(Message::Text(JOIN.into())).await.unwrap();
            assert_eq!(text(&mut client).await, large_ack);
            assert_eq!(text(&mut client).await, "2");
            client.send(Message::Text("3".into())).await.unwrap();
            client
                .send(Message::Text(large_input.clone().into()))
                .await
                .unwrap();
            assert_eq!(text(&mut client).await, ACK);
            assert_eq!(text(&mut client).await, "2");
            client.send(Message::Text("3".into())).await.unwrap();
            observed.await.unwrap();
            fixture
                .assert_idle_publishes_and_admits_next_request()
                .await;
        })
        .await
        .expect("large messages must not stall later bidirectional Engine.IO traffic");
        if let Some(admissions) = admissions {
            assert_eq!(admissions.load(Ordering::SeqCst), 1);
        }
        assert_complete_recording(&fixture, &large_input, &large_ack);
    });
}

fn assert_complete_recording(fixture: &ManagedSocketFixture, input: &str, ack: &str) {
    for group in std::fs::read_dir(fixture.state.recorder().run_dir.join("apis")).unwrap() {
        for case in std::fs::read_dir(group.unwrap().path()).unwrap() {
            let request_path = case.unwrap().path().join("request.json");
            let request: serde_json::Value = serde_json::from_slice(
                &crate::request_headers::load_request_file(&request_path).unwrap(),
            )
            .unwrap();
            if request["interaction"]["protocol"] != "socket_io" {
                continue;
            }
            let program: InputTranscript =
                serde_json::from_value(request["interaction"].clone()).unwrap();
            program.validate().unwrap();
            let messages = program
                .actions
                .iter()
                .filter_map(|action| {
                    if let InputActionKind::Message { message } = &action.action {
                        Some(message.data.as_str())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            assert!(messages.contains(&input));
            assert_eq!(
                messages.iter().filter(|message| **message == "3").count(),
                2
            );
            let expected_path = request_path.with_file_name("expected-response.json");
            let mut expected =
                serde_json::from_slice(&std::fs::read(&expected_path).unwrap()).unwrap();
            crate::interaction::private::decrypt_output(&mut expected, &expected_path).unwrap();
            let output: OutputObservation =
                serde_json::from_value(expected["interaction"].clone()).unwrap();
            assert!(output.events.iter().any(|event| event.message.data == ack));
            assert_eq!(
                output
                    .events
                    .iter()
                    .filter(|event| event.heartbeat && event.message.data == "2")
                    .count(),
                2
            );
            assert_eq!(output.end.reason, EndReason::BusinessIdle);
            assert!(output.end.clean);
            assert!(output.end.pending.is_empty());
            return;
        }
    }
    panic!("the Socket.IO case must be published with its full input and output");
}
