use super::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn records_proxy_http_client_timeout() {
    capture_timeout(false, false).await;
}

#[tokio::test]
async fn records_proxy_https_client_timeout_during_upstream_tls_handshake() {
    capture_timeout(true, false).await;
}

#[tokio::test]
async fn proxy_http_client_fin_preserves_delayed_response() {
    capture_timeout(false, true).await;
}
#[tokio::test]
async fn proxy_https_client_fin_preserves_delayed_response() {
    capture_timeout(true, true).await;
}

trait TestStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestStream for T {}

async fn capture_timeout(tls: bool, half_close: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.traffic_jsonl = crate::TrafficJsonlMode::Full;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    config.http.listen = proxy_addr;
    let mut state = AppState::new(config).await.unwrap();
    if tls && half_close {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(state.ca().ca_cert_der()).unwrap();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();
        Arc::get_mut(&mut state.inner).unwrap().client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(crate::http::client::ObservedConnector::new(connector));
    }
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
    let server_config = state.ca().server_config_for_host("127.0.0.1").unwrap();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut stream: Box<dyn TestStream> = if tls && half_close {
            Box::new(
                tokio_rustls::TlsAcceptor::from(server_config)
                    .accept(stream)
                    .await
                    .unwrap(),
            )
        } else {
            Box::new(stream)
        };
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        sent.send(()).unwrap();
        if half_close {
            tokio::time::sleep(Duration::from_millis(120)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        } else {
            // HTTP waits for headers; HTTPS waits for an upstream TLS handshake.
            std::future::pending::<()>().await;
        }
    });
    let proxy_task = tokio::spawn(run_with_listener(state.clone(), listener));
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let control = crate::dependency::termination::ConnectionControl::new(&stream).unwrap();
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
    if half_close {
        control.shutdown_write().unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"ok"));
    } else {
        control.reset().unwrap();
    }
    drop(client);
    assert!(
        state
            .drain_active_case_dependencies(case.id)
            .await
            .is_none()
    );
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().flush_traffic().await.unwrap();
    let raw = crate::recorder::test_io::read_to_string(
        state.recorder().case_dir(&case).join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let events: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    let outcome: crate::DependencyExchangeOutcome =
        serde_json::from_value(events[0]["outcome"].clone()).unwrap();
    assert_eq!(outcome.is_client_terminated(), !half_close);
    if half_close {
        assert_eq!(outcome, crate::DependencyExchangeOutcome::Response);
    }
    assert_eq!(events[0]["request_body"]["encoding"], "base64");
    assert_eq!(events[0]["request_body"]["data"], "Ym9keQ==");
    assert_eq!(events[0]["response_status"].is_null(), !half_close);
    assert!(events[0]["error"].is_null());
    let traffic =
        crate::recorder::test_io::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
    assert!(traffic.lines().any(|line| {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        event["event_type"] == "http_exchange"
            && serde_json::from_value::<crate::DependencyExchangeOutcome>(event["outcome"].clone())
                .is_ok_and(|outcome| outcome.is_client_terminated() != half_close)
    }));
    proxy_task.abort();
    upstream_task.abort();
}
