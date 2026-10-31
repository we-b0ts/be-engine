//! Exercise actual peer FIN/RST through Recorder and its immutable Replay evidence.
use super::*;
use crate::dependency::termination::ConnectionControl;
use std::time::Duration;

#[tokio::test]
async fn records_and_replays_http_server_eof_before_headers() {
    exercise(false, false).await;
}
#[tokio::test]
async fn records_and_replays_http_server_reset_before_headers() {
    exercise(true, false).await;
}
#[tokio::test]
async fn records_and_replays_http_server_eof_after_response_prefix() {
    exercise(false, true).await;
}
#[tokio::test]
async fn records_and_replays_http_server_reset_after_response_prefix() {
    exercise(true, true).await;
}

async fn exercise(reset: bool, prefix: bool) {
    tokio::time::timeout(
        Duration::from_secs(5),
        capture_and_replay(reset, prefix, false),
    )
    .await
    .unwrap();
}

async fn capture_and_replay(reset: bool, prefix: bool, extra_input: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.recording.case_dependency_post_response_window_ms = 0;
    let recorder = crate::AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: uuid::Uuid::new_v4(),
        rule_name: "server-end".into(),
        uri_group: None,
    };
    let guard = recorder.try_reserve_active_case(case.clone()).unwrap();
    recorder.activate_case_dependencies(&guard).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = upstream.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let control = ConnectionControl::new(&stream).unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        if prefix {
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n").await.unwrap();
            stream.flush().await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        if reset {
            control.reset().unwrap();
        } else {
            control.shutdown_write().unwrap();
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(crate::proxy::http::run_with_listener(
        recorder.clone(),
        listener,
    ));
    let mut source = TcpStream::connect(address).await.unwrap();
    source
        .write_all(
            format!("GET http://{authority}/server-end HTTP/1.1\r\nHost: {authority}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let captured = read_termination(&mut source, reset).await;
    assert_prefix(&captured, prefix);
    if !reset {
        source
            .write_all(b"source-write-half-remains-open")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            source.take_error().unwrap().is_none(),
            "forwarded server FIN must not discard Source's still-open write half"
        );
    }
    peer.await.unwrap();
    assert!(
        recorder
            .drain_active_case_dependencies(case.id)
            .await
            .is_none()
    );
    assert!(recorder.active_case_invalidation(case.id).is_none());
    recorder.recorder().publish_case(&case).await.unwrap();
    recorder.recorder().flush_traffic().await.unwrap();
    let case_dir = recorder.recorder().case_dir(&case);
    let raw = crate::recorder::test_io::read_to_string(case_dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    let event: Value = serde_json::from_str(raw.trim()).unwrap();
    let outcome: crate::DependencyExchangeOutcome =
        serde_json::from_value(event["outcome"].clone()).unwrap();
    assert!(outcome.is_server_terminated());
    assert!(event["error"].is_null());
    if prefix {
        assert_eq!(event["response_stream"]["complete"], true);
    }
    drop(guard);
    if !reset {
        source.shutdown().await.unwrap();
    }
    drop(source);
    proxy.abort();
    assert!(!recorder.recorder().finish_run().await.unwrap());

    let (address, runtime, replay) = spawn_http_replay(&case_dir, Vec::new()).await;
    let mut target = TcpStream::connect(address).await.unwrap();
    let started = tokio::time::Instant::now();
    target
        .write_all(format!("GET /server-end HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let delivered = read_termination(&mut target, reset).await;
    assert_prefix(&delivered, prefix);
    assert!(started.elapsed() >= Duration::from_millis(60));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.state.lock().await.http_events.matched_count == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    if extra_input {
        target
            .write_all(b"GET /unexpected HTTP/1.1\r\nHost: dependency.test\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if runtime.state.lock().await.http_exchanges[0].status
                    == crate::replay::ReplayExchangeStatus::Failed
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let state = runtime.state.lock().await;
        assert!(
            state
                .http_events
                .unsupported
                .iter()
                .any(|event| event.reason.contains("additional HTTP dependency input"))
        );
        replay.abort();
        return;
    }
    let state = runtime.state.lock().await;
    assert!(state.http_events.unsupported.is_empty());
    assert!(state.http_exchanges[0].status.is_consumed());
    replay.abort();
}

async fn read_termination(stream: &mut TcpStream, reset: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    let result = stream.read_to_end(&mut bytes).await;
    if reset {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
    } else {
        result.unwrap();
    }
    bytes
}

fn assert_prefix(bytes: &[u8], prefix: bool) {
    if prefix {
        assert!(bytes.starts_with(b"HTTP/1.1 200"));
        assert!(bytes.ends_with(b"3\r\none\r\n"));
        assert!(!bytes.ends_with(b"0\r\n\r\n"));
    } else {
        assert!(
            bytes.is_empty(),
            "server termination must not synthesize HTTP headers"
        );
    }
}

#[tokio::test]
async fn replay_http_input_after_server_fin_marks_dependency_dirty() {
    tokio::time::timeout(
        Duration::from_secs(5),
        capture_and_replay(false, true, true),
    )
    .await
    .unwrap();
}
