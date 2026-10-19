use super::*;
use crate::recorder::CaseContext;
use brz_redis::RedisService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

mod renewal;
mod reuse;

const BOUND: Duration = Duration::from_secs(3);

async fn state(temp: &tempfile::TempDir) -> crate::AppState {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.dns_mock.registry_path = temp.path().join("dns.json");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.recording.encrypt_request_headers.clear();
    let state = crate::AppState::new(config).await.unwrap();
    state
        .close_bootstrap("relay interaction test ready")
        .await
        .unwrap();
    state
}

struct Fixture {
    relay: Relay<RedisService>,
    address: std::net::SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Fixture {
    async fn new(state: crate::AppState, origin: std::net::SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = Relay::new(
            None,
            format!("http://{origin}").parse().unwrap(),
            "all-apis".into(),
            BOUND,
            1024,
        )
        .with_interactions(state, format!("http://{address}").parse().unwrap());
        relay.open();
        let (stop, stopping) = watch::channel(false);
        let task = tokio::spawn(serve(listener, relay.clone(), stopping));
        Self {
            relay,
            address,
            stop,
            task,
        }
    }

    async fn request(&self, path: &str, accept: Option<&str>) -> Response<Incoming> {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let mut request = Request::builder()
            .uri(format!("http://{}{path}", self.address))
            .header(wire::CASE_ID, "forged-case")
            .header(wire::SESSION_ID, "forged-session");
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        tokio::time::timeout(
            BOUND,
            client.request(request.body(Full::new(Bytes::new())).unwrap()),
        )
        .await
        .unwrap()
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

async fn head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}

fn case() -> CaseContext {
    CaseContext {
        id: Uuid::new_v4(),
        rule_name: "relay".into(),
        uri_group: None,
    }
}

#[tokio::test]
async fn stream_bytes_arrive_before_eof_and_slot_waits_for_inner_cleanup() {
    stream_roundtrip(
        Some("text/event-stream"),
        "text/event-stream",
        "data: x\n\n",
    )
    .await;
    stream_roundtrip(None, "application/x-ndjson", "{\"x\":1}\n").await;
}

async fn stream_roundtrip(accept: Option<&str>, content_type: &'static str, payload: &'static str) {
    let temp = tempfile::tempdir().unwrap();
    let state = state(&temp).await;
    let case = case();
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(state.clone(), inner.local_addr().unwrap()).await;
    let (finish, finished) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = inner.accept().await.unwrap();
        let request = head(&mut stream).await;
        assert!(!request.contains("x-traffic-e2e-"));
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nx-traffic-e2e-case-id: {}\r\nx-traffic-e2e-session-id: private-sid\r\n\r\n{:X}\r\n{payload}\r\n", case.id, payload.len()).as_bytes()).await.unwrap();
        finished.await.unwrap();
        stream.write_all(b"0\r\n\r\n").await.unwrap();
    });
    let mut response = fixture.request("/events", accept).await;
    assert!(response.headers().get(wire::CASE_ID).is_none());
    assert!(response.headers().get(wire::SESSION_ID).is_none());
    let first = tokio::time::timeout(BOUND, response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, payload);
    finish.send(()).unwrap();
    response.into_body().collect().await.unwrap();
    assert_eq!(
        fixture.relay.slot.available_permits(),
        0,
        "EOF cannot release pending inner cleanup"
    );
    drop(guard);
    tokio::time::timeout(BOUND, fixture.relay.drain())
        .await
        .unwrap();
    upstream.await.unwrap();
}

#[tokio::test]
async fn polling_followups_share_the_case_slot_and_unknown_sid_cannot_acquire_one() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(&temp).await;
    let case = case();
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(state.clone(), inner.local_addr().unwrap()).await;
    let upstream = tokio::spawn(async move {
        for path in [
            "/socket.io/?EIO=4&transport=polling",
            "/socket.io/?EIO=4&transport=polling&sid=session",
            "/socket.io/?EIO=4&transport=polling&sid=unknown",
        ] {
            let (mut stream, _) = inner.accept().await.unwrap();
            let request = head(&mut stream).await;
            assert!(request.starts_with(&format!("GET {path} HTTP/1.1")));
            let headers = if path.ends_with("unknown") {
                "400 Bad Request\r\n".to_owned()
            } else {
                format!(
                    "200 OK\r\nx-traffic-e2e-case-id: {}\r\nx-traffic-e2e-session-id: session\r\n",
                    case.id
                )
            };
            stream
                .write_all(
                    format!("HTTP/1.1 {headers}Content-Length: 2\r\nConnection: close\r\n\r\nok")
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    for sid in ["", "&sid=session", "&sid=unknown"] {
        let response = fixture
            .request(&format!("/socket.io/?EIO=4&transport=polling{sid}"), None)
            .await;
        assert_eq!(
            response.status(),
            if sid.ends_with("unknown") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            }
        );
        response.into_body().collect().await.unwrap();
        assert_eq!(fixture.relay.slot.available_permits(), 0);
    }
    let busy = fixture.request("/ordinary", None).await;
    assert_eq!(busy.status(), StatusCode::NOT_FOUND);
    drop(guard);
    tokio::time::timeout(BOUND, fixture.relay.drain())
        .await
        .unwrap();
    upstream.await.unwrap();
}

#[tokio::test]
async fn direct_upgrade_preserves_duplex_bytes_and_closes_after_case_release() {
    let temp = tempfile::tempdir().unwrap();
    let state = state(&temp).await;
    let case = case();
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = Fixture::new(state.clone(), inner.local_addr().unwrap()).await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = inner.accept().await.unwrap();
        assert!(
            head(&mut stream)
                .await
                .to_lowercase()
                .contains("upgrade: websocket")
        );
        stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nx-traffic-e2e-case-id: {}\r\n\r\n", case.id).as_bytes()).await.unwrap();
        let mut message = [0; 4];
        stream.read_exact(&mut message).await.unwrap();
        stream.write_all(&message).await.unwrap();
        assert_eq!(stream.read(&mut message).await.unwrap(), 0);
    });
    let mut client = TcpStream::connect(fixture.address).await.unwrap();
    client.write_all(b"GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
    let response = tokio::time::timeout(BOUND, head(&mut client))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 101"));
    assert!(!response.contains("x-traffic-e2e-"));
    client.write_all(b"ping").await.unwrap();
    let mut message = [0; 4];
    tokio::time::timeout(BOUND, client.read_exact(&mut message))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&message, b"ping");
    assert_eq!(fixture.relay.slot.available_permits(), 0);
    drop(guard);
    assert_eq!(
        tokio::time::timeout(BOUND, client.read(&mut message))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    tokio::time::timeout(BOUND, fixture.relay.drain())
        .await
        .unwrap();
    upstream.await.unwrap();
}
