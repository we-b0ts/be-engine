//! One case spans polling requests, probe, and WebSocket upgrade.

use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

struct Peer {
    sid: &'static str,
    tx: mpsc::Sender<String>,
    rx: Mutex<mpsc::Receiver<String>>,
    upgraded: AtomicBool,
    websocket: std::sync::Mutex<Option<JoinHandle<()>>>,
}

fn spawn_peer(listener: TcpListener, sid: &'static str) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    let peer = Arc::new(Peer {
        sid,
        tx,
        rx: Mutex::new(rx),
        upgraded: AtomicBool::new(false),
        websocket: std::sync::Mutex::new(None),
    });
    let (stop, mut stopping) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut stopping => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    let peer = peer.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |request| dispatch(peer.clone(), request));
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service).with_upgrades().await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        let websocket = peer.websocket.lock().unwrap().take();
        if let Some(websocket) = websocket {
            websocket.abort();
            let _ = websocket.await;
        }
    });
    (stop, task)
}

async fn dispatch(
    peer: Arc<Peer>,
    mut request: Request<hyper::body::Incoming>,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    let sid = super::super::query(request.uri(), "sid");
    let response = if sid.as_deref().is_some_and(|sid| sid != peer.sid) {
        hyper::Response::builder()
            .status(400)
            .body(Full::new(Bytes::from_static(b"wrong sid")))
            .unwrap()
    } else if request.headers().contains_key("upgrade") {
        let key = request
            .headers()
            .get("sec-websocket-key")
            .unwrap()
            .as_bytes();
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key);
        let upgraded = hyper::upgrade::on(&mut request);
        let websocket_peer = peer.clone();
        let websocket = tokio::spawn(async move {
            let socket = upgraded.await.unwrap();
            let mut socket = WebSocketStream::from_raw_socket(
                hyper_util::rt::TokioIo::new(socket),
                Role::Server,
                None,
            )
            .await;
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "2probe"
            );
            socket.send(Message::Text("3probe".into())).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "5"
            );
            websocket_peer.upgraded.store(true, Ordering::SeqCst);
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "422[\"ask\",2]"
            );
            socket.send(Message::Text("432[2]".into())).await.unwrap();
            match socket.next().await {
                Some(Ok(Message::Text(text))) if text == "1" => {
                    let _ = socket.close(None).await;
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {}
                message => panic!("unexpected upgraded input: {message:?}"),
            }
        });
        *peer.websocket.lock().unwrap() = Some(websocket);
        let _ = peer.tx.send("6".into()).await;
        hyper::Response::builder()
            .status(101)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(Full::new(Bytes::new()))
            .unwrap()
    } else {
        let data = if sid.is_none() {
            format!(
                "0{{\"sid\":\"{}\",\"upgrades\":[\"websocket\"],\"pingInterval\":25,\"pingTimeout\":1000}}",
                peer.sid
            )
        } else if request.method() == hyper::Method::GET {
            peer.rx
                .lock()
                .await
                .recv()
                .await
                .unwrap_or_else(|| "1".into())
        } else {
            if peer.upgraded.load(Ordering::SeqCst) {
                return Ok(hyper::Response::builder()
                    .status(400)
                    .body(Full::new(Bytes::from_static(b"polling after upgrade")))
                    .unwrap());
            }
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            match bytes.as_ref() {
                b"40" => peer
                    .tx
                    .send(format!("40{{\"sid\":\"{}-namespace\"}}", peer.sid))
                    .await
                    .unwrap(),
                b"421[\"ask\",1]" => peer.tx.send("431[1]".into()).await.unwrap(),
                b"1" => {
                    let _ = peer.tx.send("1".into()).await;
                }
                value => panic!("unexpected polling input: {value:?}"),
            }
            "ok".into()
        };
        hyper::Response::builder()
            .header("content-type", "text/plain; charset=UTF-8")
            .body(Full::new(Bytes::from(data)))
            .unwrap()
    };
    Ok(response)
}

async fn polling_request(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    uri: &str,
    body: Option<&str>,
) -> String {
    let request = Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(uri)
        .body(Full::new(Bytes::copy_from_slice(
            body.unwrap_or("").as_bytes(),
        )))
        .unwrap();
    let response = client.request(request).await.unwrap();
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

#[tokio::test]
async fn polling_and_upgrade_record_as_one_case_and_replay_with_a_new_sid() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    // Leave scheduling room for the polling/probe/upgrade round trips in the full suite.
    settings.http_gateway.interaction.business_idle_ms = 500;
    let state = AppState::new(settings).await.unwrap();
    let (source_stop, source) = spawn_peer(upstream, "recorded-source-sid");
    let (address, recording) = gateway(state.clone()).await;
    let client = Client::builder(TokioExecutor::new()).build_http();
    let uri = format!("http://{address}/socket.io/?EIO=4&transport=polling");
    assert!(
        polling_request(&client, &uri, None)
            .await
            .contains("recorded-source-sid")
    );
    let uri = format!("{uri}&sid=recorded-source-sid");
    assert_eq!(polling_request(&client, &uri, Some("40")).await, "ok");
    assert!(polling_request(&client, &uri, None).await.starts_with("40"));
    polling_request(&client, &uri, Some("421[\"ask\",1]")).await;
    assert_eq!(polling_request(&client, &uri, None).await, "431[1]");
    let (mut socket, _) = tokio_tungstenite::connect_async(format!(
        "ws://{address}/socket.io/?EIO=4&transport=websocket&sid=recorded-source-sid"
    ))
    .await
    .unwrap();
    socket.send(Message::Text("2probe".into())).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "3probe"
    );
    socket.send(Message::Text("5".into())).await.unwrap();
    socket
        .send(Message::Text("422[\"ask\",2]".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "432[2]"
    );
    assert!(matches!(
        timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_)))
    ));
    let case = published(&state).await;
    assert!(!*state.inner.interactions.source_stop.borrow());
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let (target_stop, target) = spawn_peer(target_listener, "different-live-target-sid");
    assert!(replay_case(&case, target_addr).await.end.clean);
    let _ = target_stop.send(());
    target.await.unwrap();
    let _ = source_stop.send(());
    source.await.unwrap();
    recording.abort();
}
