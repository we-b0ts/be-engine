//! The managed ingress and recording gateway must share Socket.IO lifetime.
use super::*;
use futures_util::{SinkExt as _, StreamExt as _};
use std::net::SocketAddr;
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request as UpgradeRequest, Response as UpgradeResponse,
};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

const OPEN: &str = r#"0{"sid":"source-session","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#;

mod large_frames;

struct BodylessHandshake;

impl Callback for BodylessHandshake {
    fn on_request(
        self,
        request: &UpgradeRequest,
        response: UpgradeResponse,
    ) -> Result<UpgradeResponse, ErrorResponse> {
        // Model Source's websockets Sans-I/O parser, including zero lengths.
        assert!(!request.headers().contains_key("content-length"));
        assert!(!request.headers().contains_key("transfer-encoding"));
        Ok(response)
    }
}

struct ManagedSocketFixture {
    state: crate::AppState,
    relay: proxy::Relay<RedisService>,
    url: String,
    tasks: Vec<JoinHandle<()>>,
    _temp: tempfile::TempDir,
}

impl Drop for ManagedSocketFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl ManagedSocketFixture {
    async fn new(source: SocketAddr) -> Self {
        Self::with_interaction(source, |_| {}).await
    }

    async fn with_interaction(
        source: SocketAddr,
        configure: impl FnOnce(&mut crate::interaction::policy::InteractionPolicy),
    ) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".traffic-e2e/local")).unwrap();
        crate::platform::encryption_key::load_or_create(temp.path()).unwrap();
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        let mut config = crate::AppConfig::default();
        config.http.enabled = false;
        config.mysql.enabled = false;
        config.http_gateway.enabled = true;
        config.http_gateway.record_streaming = true;
        config.http_gateway.listen = gateway_address;
        config.http_gateway.matched_upstream = format!("http://{source}");
        config.http_gateway.fallback_upstream = format!("http://{source}");
        config.http_gateway.request_timeout_ms = 1_500;
        config.http_gateway.interaction.business_idle_ms = 100;
        config.http_gateway.interaction.input_gap_ms = 1;
        config.http_gateway.interaction.max_duration_ms = 2_000;
        config.http_gateway.interaction.cleanup_timeout_ms = 1_000;
        configure(&mut config.http_gateway.interaction);
        config.http_gateway.rules = vec![crate::HttpGatewayRuleConfig {
            name: Some("managed-socketio".into()),
            path_prefixes: vec!["/".into()],
            ..Default::default()
        }];
        config.recording.output_dir = temp.path().join(".traffic-e2e/local/artifacts/recordings");
        config.recording.case_dependency_post_response_window_ms = 0;
        config.recording.api_origin_dependency_idle_ms = 10;
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = crate::AppState::new(config).await.unwrap();
        let gateway_state = state.clone();
        let gateway = tokio::spawn(async move {
            crate::gateway::http::run_with_listener(gateway_state, gateway_listener)
                .await
                .unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let relay: proxy::Relay<RedisService> = proxy::Relay::new(
            None,
            format!("http://{gateway_address}").parse().unwrap(),
            "all-apis".into(),
            Duration::from_secs(2),
            1024 * 1024,
        )
        .with_interactions(state.clone(), url.parse().unwrap());
        relay.open();
        let (stop, stopped) = watch::channel(false);
        let running = relay.clone();
        let adapter = tokio::spawn(async move {
            let _stop = stop;
            proxy::serve(listener, running, stopped).await.unwrap();
        });
        Self {
            state,
            relay,
            url,
            tasks: vec![gateway, adapter],
            _temp: temp,
        }
    }

    async fn request(&self, path: &str) -> Bytes {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("{}{path}", self.url))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap().to_bytes()
    }

    async fn assert_idle_publishes_and_admits_next_request(&self) {
        assert!(
            self.state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await,
            "Socket.IO business idle must finish the recorded case"
        );
        self.relay.drain().await;
        assert_eq!(self.request("/api/next").await.as_ref(), b"next");
        assert!(
            self.state
                .inner
                .active_cases
                .wait_for_no_active_case(Duration::from_secs(2))
                .await
        );
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.state.recorder().run_dir.join("recording-run.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report["published_cases"], 2);
        assert_eq!(report["failed_cases"], 0);
    }
}

async fn send_http_response(stream: &mut tokio::net::TcpStream, body: &str) {
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}

#[test]
fn managed_socketio_polling_initial_request_reaches_source_and_idle_releases_slot() {
    runtime().block_on(async {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = ManagedSocketFixture::new(source.local_addr().unwrap()).await;
        fixture.tasks.push(tokio::spawn(async move {
            loop {
                let (mut stream, _) = source.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                let body = if request.starts_with("GET /socket.io/") {
                    OPEN
                } else if request.starts_with("POST /socket.io/") {
                    assert!(request.ends_with('1'), "cleanup must send Engine.IO CLOSE");
                    "ok"
                } else {
                    assert!(request.starts_with("GET /api/next "));
                    "next"
                };
                send_http_response(&mut stream, body).await;
            }
        }));
        tokio::time::timeout(Duration::from_secs(4), async {
            assert_eq!(
                fixture
                    .request("/socket.io/?EIO=4&transport=polling")
                    .await
                    .as_ref(),
                OPEN.as_bytes()
            );
            fixture
                .assert_idle_publishes_and_admits_next_request()
                .await;
        })
        .await
        .expect("managed polling must forward the initial request and close on business idle");
    });
}

#[test]
fn managed_socketio_websocket_handshake_reaches_source_and_idle_releases_slot() {
    websocket_handshake(false);
}

#[test]
fn managed_socketio_websocket_accepts_legacy_gateway_zero_content_length() {
    websocket_handshake(true);
}

fn websocket_handshake(zero_content_length: bool) {
    runtime().block_on(async {
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = ManagedSocketFixture::new(source.local_addr().unwrap()).await;
        fixture.tasks.push(tokio::spawn(async move {
            let (stream, _) = source.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(stream, BodylessHandshake)
                .await
                .unwrap();
            socket.send(Message::Text(OPEN.into())).await.unwrap();
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
        tokio::time::timeout(Duration::from_secs(4), async {
            let url = format!(
                "{}/socket.io/?EIO=4&transport=websocket",
                fixture.url.replacen("http://", "ws://", 1)
            );
            let mut request = url.into_client_request().unwrap();
            if zero_content_length {
                request
                    .headers_mut()
                    .insert("content-length", "0".parse().unwrap());
            }
            let (mut client, _) = tokio_tungstenite::connect_async(request).await.unwrap();
            assert_eq!(
                client.next().await.unwrap().unwrap().into_text().unwrap(),
                OPEN
            );
            fixture
                .assert_idle_publishes_and_admits_next_request()
                .await;
        })
        .await
        .expect("managed WebSocket must complete both upgrades and close on business idle");
    });
}
