use super::*;
use bytes::Bytes;
use http_body_util::Full;
use std::{collections::BTreeMap, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

#[tokio::test]
async fn ordinary_close_delimited_json_requires_independent_eof() {
    for engine_cleanup in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();
        let termination = ClientTermination::default();
        let context = HttpCaptureContext {
            targets: state.capture_dependency_targets(),
            state,
            event: event(),
            started: Instant::now(),
            termination: termination.clone(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (close, closed) = tokio::sync::oneshot::channel();
        let source = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.unwrap());
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}").await.unwrap();
            closed.await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let socket = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
                .await
                .unwrap();
        let connection = tokio::spawn(connection);
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri("/json")
                    .header("host", "dependency.test")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!crate::protocols::recording::http::stream::is_stream(
            response.headers()
        ));
        let collected = context.collect_response_body(response.into_body());
        tokio::pin!(collected);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut collected)
                .await
                .is_err(),
            "valid JSON bytes do not complete a connection-delimited HTTP body"
        );
        if engine_cleanup {
            termination.connection_observation().observe_engine_stop();
        }
        close.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), &mut collected)
            .await
            .unwrap();
        if engine_cleanup {
            assert!(result.unwrap_err().to_string().contains("engine cleanup"));
        } else {
            assert_eq!(result.unwrap(), "{\"ok\":true}");
            termination.connection_observation().observe_engine_stop();
        }
        source.await.unwrap();
        connection.abort();
    }
}

fn event() -> HttpExchangeEvent {
    HttpExchangeEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        request_started_at: Utc::now(),
        outcome: DependencyExchangeOutcome::Response,
        client_addr: None,
        upstream_addr: None,
        scheme: "http".into(),
        method: "GET".into(),
        uri: "/json".into(),
        authority: Some("dependency.test".into()),
        request_headers: BTreeMap::new(),
        request_body: crate::recorder::capture_body(b"", 10),
        response_status: None,
        response_headers: None,
        response_body: None,
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 0,
        error: None,
    }
}

#[tokio::test]
async fn pending_request_records_no_response_after_verified_source_exit() {
    use traffic_model::session::SessionEvent;

    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.session_events = true;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    state.session_event(SessionEvent::SourceStart).unwrap();
    state.session_event(SessionEvent::Ready).unwrap();
    let event = event();
    let targets = state.capture_dependency_start(
        crate::dependency::observation::ProtocolRef::exchange("http", event.id),
    );
    let sequence = targets.capture.as_ref().unwrap().dependency_id();
    let termination = ClientTermination::default();
    let pending = PendingHttpCapture::new(
        state.clone(),
        targets,
        event,
        Instant::now(),
        termination.clone(),
    );
    state.session_event(SessionEvent::Stop).unwrap();
    state
        .session_event(SessionEvent::SourceExit {
            status: Some(0),
            forced_by_recorder: false,
        })
        .unwrap();
    termination
        .connection_observation()
        .observe_engine_stop_at_boundary(Instant::now());
    drop(pending);
    state
        .recorder()
        .finish_run_after_runtime(true)
        .await
        .unwrap();

    let root = &state.recorder().run_dir;
    let record = traffic_recording_store::session_records::dependency(root, sequence).unwrap();
    assert_eq!(record["outcome"], "no_response");
    assert!(record["response_status"].is_null());
    assert!(record["error"].is_null());
    assert!(
        std::fs::read_to_string(root.join("events.tsv"))
            .unwrap()
            .lines()
            .any(|line| line.ends_with(&format!("\twire_output\t{sequence}\ttarget_stop")))
    );
}
