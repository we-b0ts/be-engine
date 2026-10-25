use super::*;
use crate::{AppState, http::termination::ClientTermination, recorder::HttpExchangeEvent};
use std::collections::BTreeMap;
use std::time::Instant;
use uuid::Uuid;

#[tokio::test]
async fn engine_body_drop_without_peer_termination_remains_a_capture_failure() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "dropped-stream".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let mut capture = Capture::new(context(&state, ClientTermination::default()));
    capture.bytes(b"prefix");
    drop(capture);
    let invalidation = state
        .active_case_invalidation(case.id)
        .expect("engine truncation must invalidate capture");
    assert_eq!(invalidation.reason, "http_stream_capture_incomplete");
    assert!(
        !invalidation.can_recover_after_drain(),
        "unexplained engine body drop still requires isolation"
    );
    let diagnosis = invalidation.context.unwrap().http_stream.unwrap();
    assert_eq!(diagnosis["client"]["engine_stopped"], false);
    assert_eq!(
        diagnosis["client"]["client_connection_end"],
        serde_json::Value::Null
    );
    assert_eq!(diagnosis["received_bytes"], 6);
    assert_eq!(diagnosis["prefix_flushed"], false);
}

fn context(state: &AppState, termination: ClientTermination) -> CaptureContext {
    let event = HttpExchangeEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        request_started_at: Utc::now(),
        outcome: crate::DependencyExchangeOutcome::Response,
        client_addr: None,
        scheme: "http".into(),
        method: "GET".into(),
        uri: "/stream".into(),
        authority: Some("dependency.test".into()),
        request_headers: BTreeMap::new(),
        request_body: crate::recorder::capture_body(b"", 10),
        response_status: Some(200),
        response_headers: Some(BTreeMap::new()),
        response_body: None,
        response_stream: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 0,
        error: None,
    };
    CaptureContext {
        targets: state.capture_dependency_targets(),
        state: state.clone(),
        event,
        started: Instant::now(),
        termination,
    }
}

#[tokio::test]
async fn client_cancellation_with_unflushed_body_prefix_fails_closed_and_retains_payload() {
    cancellation_with_backpressure(false).await;
}

#[tokio::test]
async fn client_cancellation_with_flushed_body_prefix_keeps_complete_evidence() {
    cancellation_with_backpressure(true).await;
}

#[tokio::test]
async fn engine_cleanup_cannot_certify_close_delimited_dependency_eof() {
    close_delimited_eof(true).await;
}

#[tokio::test]
async fn independent_close_delimited_eof_stays_complete_after_later_engine_cleanup() {
    close_delimited_eof(false).await;
}

async fn close_delimited_eof(engine_cleanup: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "close-delimited-stream".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (close, closed) = tokio::sync::oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        // No length or chunk framing: the actual TCP EOF delimits this body.
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nprefix")
            .await
            .unwrap();
        closed.await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
            .await
            .unwrap();
    let connection = tokio::spawn(connection);
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("/stream")
                .header("host", "dependency.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let termination = ClientTermination::default();
    let mut body = CaptureBody {
        body: response.into_body(),
        capture: Capture::new(context(&state, termination.clone())),
        ending: None,
    };
    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        "prefix"
    );
    if engine_cleanup {
        termination.connection_observation().observe_engine_stop();
    }
    close.send(()).unwrap();
    assert!(
        body.frame().await.is_none(),
        "Hyper should observe body EOF"
    );
    if !engine_cleanup {
        // A subsequent global cleanup cannot revoke an already observed EOF.
        termination.connection_observation().observe_engine_stop();
        body.capture.finish(true, None);
    }
    drop(body);
    assert_eq!(
        state.active_case_invalidation(case.id).is_some(),
        engine_cleanup
    );
    assert!(
        state
            .drain_active_case_dependencies(case.id)
            .await
            .is_none()
    );
    state
        .recorder()
        .flush_case_dependency_files(&state.recorder().case_staging_dir(&case))
        .await
        .unwrap();
    let raw = tokio::fs::read_to_string(
        state
            .recorder()
            .case_staging_dir(&case)
            .join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let evidence: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(evidence["response_body"]["data"], "cHJlZml4");
    assert_eq!(evidence["response_stream"]["complete"], !engine_cleanup);
    if engine_cleanup {
        assert!(
            evidence["error"]
                .as_str()
                .unwrap()
                .contains("engine cleanup")
        );
    } else {
        assert!(evidence["error"].is_null());
    }
    source.await.unwrap();
    connection.abort();
}

async fn cancellation_with_backpressure(flushed: bool) {
    use crate::http::termination::ObservedClientIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "backpressure".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let source = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nprefix\r\n").await.unwrap();
        std::future::pending::<()>().await;
    });
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
            .await
            .unwrap();
    let connection = tokio::spawn(connection);
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("/stream")
                .header("host", "dependency.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let termination = ClientTermination::default();
    let mut body = CaptureBody {
        body: response.into_body(),
        capture: Capture::new(context(&state, termination.clone())),
        ending: None,
    };
    let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(frame.as_ref(), b"prefix");
    let (downstream, _reader) = tokio::io::duplex(if flushed { 64 } else { 1 });
    let mut downstream = ObservedClientIo::new(downstream, termination.clone());
    if flushed {
        downstream.write_all(&frame).await.unwrap();
        downstream.flush().await.unwrap();
    } else {
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                downstream.write_all(&frame)
            )
            .await
            .is_err()
        );
    }
    assert_eq!(body.capture.prefix.is_complete(), flushed);
    termination
        .connection_observation()
        .observe_client_io_error(&std::io::ErrorKind::ConnectionReset.into());
    drop(body);
    assert_eq!(state.active_case_invalidation(case.id).is_none(), flushed);
    if !flushed {
        assert!(
            state
                .active_case_invalidation(case.id)
                .unwrap()
                .can_recover_after_drain()
        );
    }
    assert!(
        state
            .drain_active_case_dependencies(case.id)
            .await
            .is_none()
    );
    let _ = state
        .recorder()
        .case_dependency_safety_issue(&case)
        .await
        .unwrap();
    let raw = tokio::fs::read_to_string(
        state
            .recorder()
            .case_staging_dir(&case)
            .join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let evidence: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(evidence["response_body"]["data"], "cHJlZml4");
    assert_eq!(evidence["response_stream"]["complete"], flushed);
    if !flushed {
        assert!(evidence["error"].as_str().unwrap().contains("not flushed"));
    }
    source.abort();
    connection.abort();
}

#[tokio::test]
async fn async_source_stop_retains_only_flushed_prefix_without_certifying_response_eof() {
    for flushed in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        config.async_api.insert(
            "POST /responses".into(),
            serde_json::from_value(serde_json::json!({
                "when": {"/background":true}, "end":[{"redis":{"operation":"DEL","key":"done"}}]
            }))
            .unwrap(),
        );
        let state = AppState::new(config).await.unwrap();
        let case = crate::recorder::CaseContext {
            id: Uuid::new_v4(),
            rule_name: "async-prefix".into(),
            uri_group: None,
        };
        let guard = state.try_reserve_active_case(case.clone()).unwrap();
        state.configure_case_observation(
            case.id,
            &hyper::Method::POST,
            &"/responses".parse().unwrap(),
            br#"{"background":true}"#,
            Instant::now(),
            std::time::Duration::ZERO,
        );
        state.activate_case_dependencies(&guard).unwrap();
        let termination = ClientTermination::default();
        let mut capture = Capture::new(context(&state, termination.clone()));
        capture.bytes(b"prefix");
        if flushed {
            termination.delivery().flushed();
        }
        let drain_state = state.clone();
        let case_id = case.id;
        let draining =
            tokio::spawn(async move { drain_state.drain_active_case_dependencies(case_id).await });
        state.inner.active_cases.wait_for_quiescing().await;
        termination.connection_observation().observe_engine_stop();
        drop(capture);
        let invalidation = draining.await.unwrap();
        assert_eq!(invalidation.is_none(), flushed);
        assert_eq!(state.active_case_invalidation(case.id).is_none(), flushed);
        state
            .recorder()
            .flush_case_dependency_files(&state.recorder().case_staging_dir(&case))
            .await
            .unwrap();
        let raw = tokio::fs::read_to_string(
            state
                .recorder()
                .case_staging_dir(&case)
                .join("dependencies.jsonl"),
        )
        .await
        .unwrap();
        let recorded: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(recorded["outcome"], "response");
        assert_eq!(recorded["response_stream"]["complete"], false);
        assert!(
            recorded["error"]
                .as_str()
                .unwrap()
                .contains("engine cleanup")
        );
    }
}
