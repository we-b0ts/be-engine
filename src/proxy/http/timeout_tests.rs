use super::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn records_proxy_http_client_timeout() {
    capture_timeout(false).await;
}

#[tokio::test]
async fn records_proxy_https_client_timeout_during_upstream_tls_handshake() {
    capture_timeout(true).await;
}

trait TestStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestStream for T {}

async fn capture_timeout(tls: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.traffic_jsonl = crate::TrafficJsonlMode::Errors;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    config.http.listen = proxy_addr;
    drop(listener);
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".into(),
        uri_group: None,
    };
    let case_guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&case_guard).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = upstream.local_addr().unwrap().to_string();
    let (sent, received) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        sent.send(()).unwrap();
        // HTTP waits for headers; HTTPS waits for an upstream TLS handshake.
        std::future::pending::<()>().await;
    });
    let proxy_task = tokio::spawn(run(state.clone()));
    let mut stream = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(stream) = TcpStream::connect(proxy_addr).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let mut client: Box<dyn TestStream> = if tls {
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&response).contains("200"));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(state.ca().ca_cert_der()).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        Box::new(
            connector
                .connect(
                    rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                    stream,
                )
                .await
                .unwrap(),
        )
    } else {
        Box::new(stream)
    };
    let path = if tls {
        "/timeout".into()
    } else {
        format!("http://{authority}/timeout")
    };
    client
        .write_all(
            format!("POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 4\r\n\r\nbody")
                .as_bytes(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    let mut probe = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(80), client.read(&mut probe))
            .await
            .is_err()
    );
    client.shutdown().await.unwrap();
    drop(client);
    assert!(
        state
            .drain_active_case_dependencies(case.id)
            .await
            .is_none()
    );
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().flush_traffic().await.unwrap();
    let raw =
        tokio::fs::read_to_string(state.recorder().case_dir(&case).join("dependencies.jsonl"))
            .await
            .unwrap();
    let events: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["outcome"], "client_terminated");
    assert_eq!(events[0]["request_body"]["encoding"], "base64");
    assert_eq!(events[0]["request_body"]["data"], "Ym9keQ==");
    assert!(events[0]["response_status"].is_null());
    assert!(events[0]["error"].is_null());
    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(traffic.contains("client_terminated"));
    proxy_task.abort();
    upstream_task.abort();
}
