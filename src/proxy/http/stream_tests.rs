use super::*;
use crate::http::stream::ResponseStream;
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod cancellation;

#[tokio::test]
async fn dependency_stream_capture_delivers_incrementally_and_holds_case_dependency_until_eof() {
    tokio::time::timeout(Duration::from_secs(5), capture_stream())
        .await
        .unwrap();
}

async fn capture_stream() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.case_dependency_drain_timeout_ms = 2000;
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "stream".into(),
        uri_group: None,
    };
    let case_guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&case_guard).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = upstream.local_addr().unwrap();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n").await.unwrap();
        finished.await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        stream.write_all(b"3\r\ntwo\r\n0\r\n\r\n").await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(super::run_with_listener(state.clone(), listener));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(
        TcpStream::connect(address).await.unwrap(),
    ))
    .await
    .unwrap();
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .uri(format!("http://{authority}/stream"))
        .header(HOST, authority.to_string())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let mut response = tokio::time::timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, "one");
    let drain = tokio::spawn({
        let state = state.clone();
        let case = case.clone();
        async move { state.drain_active_case_dependencies(case.id).await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!drain.is_finished());
    finish.send(()).unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "two"
    );
    assert!(drain.await.unwrap().is_none());
    source.await.unwrap();
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().flush_traffic().await.unwrap();
    let raw = crate::recorder::test_io::read_to_string(
        state.recorder().case_dir(&case).join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let recorded: Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(recorded["response_stream"]["complete"], true);
    let timing: ResponseStream =
        serde_json::from_value(recorded["response_stream"].clone()).unwrap();
    timing.validate(6).unwrap();
    assert!(timing.chunks.len() >= 2);
    assert!(timing.chunks.last().unwrap().at_ms >= timing.chunks[0].at_ms + 70);
    assert_eq!(recorded["response_body"]["data"], "b25ldHdv");
    drop(case_guard);
    proxy.abort();
    connection.abort();
    state.recorder().finish_run().await.unwrap();
    let network = crate::recording_network::RecordingNetworkManifest::load(
        &state
            .recorder()
            .run_dir
            .join(crate::recording_network::RECORDING_NETWORK_FILENAME),
    )
    .unwrap();
    assert!(
        network.accessed_endpoints.contains(
            &crate::recording_network::RecordedEndpoint::new(
                &authority.ip().to_string(),
                authority.port()
            )
            .unwrap()
        )
    );
}
