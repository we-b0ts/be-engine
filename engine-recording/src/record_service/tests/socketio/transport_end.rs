//! A client TCP end crosses the owned ingress tunnel and retains its captured type.
use super::*;
use crate::dependency::termination::ConnectionControl;
use crate::interaction::model::{ClientTransportEnd, InputActionKind, InputTranscript};
use std::sync::atomic::AtomicBool;

struct AsgiHandshake;

impl Callback for AsgiHandshake {
    fn on_request(
        self,
        request: &UpgradeRequest,
        response: UpgradeResponse,
    ) -> Result<UpgradeResponse, ErrorResponse> {
        let mut response = BodylessHandshake.on_request(request, response)?;
        response
            .headers_mut()
            .insert("server", "uvicorn".parse().unwrap());
        Ok(response)
    }
}

async fn source(listener: TcpListener, end: ClientTransportEnd) {
    let closed = Arc::new(AtomicBool::new(false));
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let closed = closed.clone();
        tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let head = loop {
                let count = stream.peek(&mut bytes).await.unwrap();
                if bytes[..count].windows(4).any(|part| part == b"\r\n\r\n") {
                    break String::from_utf8(bytes[..count].to_vec()).unwrap();
                }
                tokio::task::yield_now().await;
            };
            if head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("upgrade: websocket"))
            {
                let mut socket = tokio_tungstenite::accept_hdr_async(stream, AsgiHandshake)
                    .await
                    .unwrap();
                socket.send(Message::Text(OPEN.into())).await.unwrap();
                assert_eq!(
                    socket.next().await.unwrap().unwrap(),
                    Message::Text("40".into())
                );
                socket.send(Message::Text("40{}".into())).await.unwrap();
                // Read below the WS decoder: no synthetic WS/Engine.IO close
                // may stand in for the client's real FIN/RST.
                let mut stream = socket.into_inner();
                let ended = stream.read(&mut [0]).await;
                match end {
                    ClientTransportEnd::Eof => assert_eq!(ended.unwrap(), 0),
                    ClientTransportEnd::Reset => {
                        assert_eq!(
                            ended.unwrap_err().kind(),
                            std::io::ErrorKind::ConnectionReset
                        );
                    }
                }
                closed.store(true, Ordering::SeqCst);
                let _ = stream.shutdown().await;
            } else {
                let request = read_request(&mut stream).await;
                assert!(request.starts_with("GET /socket.io/"));
                assert!(request.contains("sid=source-session"));
                let (status, body) = if closed.load(Ordering::SeqCst) {
                    ("400 Bad Request", "\"Invalid session source-session\"")
                } else {
                    ("200 OK", "6")
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
    }
}

#[test]
fn managed_socketio_ingress_records_the_actual_client_fin_and_reset() {
    runtime().block_on(async {
        for end in [ClientTransportEnd::Eof, ClientTransportEnd::Reset] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut fixture = ManagedSocketFixture::with_interaction(
                    listener.local_addr().unwrap(),
                    |policy| policy.business_idle_ms = 1_500,
                )
                .await;
                fixture.tasks.push(tokio::spawn(source(listener, end)));
                let (mut client, _) = tokio_tungstenite::connect_async(format!(
                    "{}/socket.io/?EIO=4&transport=websocket",
                    fixture.url.replacen("http://", "ws://", 1)
                ))
                .await
                .unwrap();
                assert_eq!(client.next().await.unwrap().unwrap(), Message::Text(OPEN.into()));
                client.send(Message::Text("40".into())).await.unwrap();
                assert_eq!(client.next().await.unwrap().unwrap(), Message::Text("40{}".into()));
                let writers = fixture.state.capture_dependency_targets();
                let case = writers.cases.first().unwrap().0.clone();
                drop(writers);
                let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = client.get_ref() else {
                    panic!("test requires raw TCP");
                };
                let control = ConnectionControl::new(tcp).unwrap();
                match end {
                    ClientTransportEnd::Eof => control.shutdown_write().unwrap(),
                    ClientTransportEnd::Reset => control.reset().unwrap(),
                }
                assert!(fixture.state.inner.active_cases.wait_for_no_active_case(Duration::from_secs(3)).await);
                fixture.relay.drain().await;
                let directory = fixture.state.recorder().case_dir(&case);
                let request: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(directory.join("request.json")).unwrap(),
                )
                .unwrap();
                let input: InputTranscript = serde_json::from_value(request["interaction"].clone()).unwrap();
                assert!(matches!(input.actions.last().map(|action|&action.action),Some(InputActionKind::TransportEnd{end:actual}) if *actual==end));
                let output: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(directory.join("expected-response.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(output["interaction"]["end"]["clean"], true);
                assert_eq!(output["interaction"]["end"]["reason"], "client_transport_end");
                assert!(output["interaction"]["end"]["close"].is_null());
                assert!(!fixture.state.inner.active_cases.is_quiescing());
                drop(client);
            })
            .await
            .expect("owned ingress must retain the actual transport end through publication");
        }
    });
}
