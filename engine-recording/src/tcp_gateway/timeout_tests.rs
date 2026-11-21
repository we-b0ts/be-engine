use super::*;
use rustls::pki_types::ServerName;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn records_http_client_termination_with_original_case_ownership() {
    capture_timeout(false, false, false).await;
}

#[tokio::test]
async fn records_https_client_termination_with_original_case_ownership() {
    capture_timeout(true, false, false).await;
}

#[tokio::test]
async fn recorder_task_cancellation_is_not_a_client_timeout() {
    capture_timeout(false, true, false).await;
}

#[tokio::test]
async fn fake_ip_http_client_fin_preserves_delayed_response() {
    capture_timeout(false, false, true).await;
}
#[tokio::test]
async fn fake_ip_https_client_fin_preserves_delayed_response() {
    capture_timeout(true, false, true).await;
}

trait TestStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TestStream for T {}

async fn capture_timeout(tls: bool, cancel_engine: bool, half_close: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.traffic_jsonl = crate::TrafficJsonlMode::Errors;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".into(),
        uri_group: None,
    };
    let case_guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&case_guard).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let size = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..size]).contains("POST /timeout"));
        sent.send(()).unwrap();
        if half_close {
            tokio::time::sleep(Duration::from_millis(120)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        } else {
            std::future::pending::<()>().await;
        }
    });
    let entry = FakeDnsEntry {
        domain: "dependency.test".into(),
        fake_ip: Ipv4Addr::new(198, 18, 0, 1),
        real_ips: vec![Ipv4Addr::LOCALHOST],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: Some(FakeDnsUpstreamProtocol::Http),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let fake_addr = SocketAddr::from((entry.fake_ip, upstream_addr.port()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway_state = state.clone();
    let gateway = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if tls {
            serve_https_mitm_connection(stream, fake_addr, entry, None, gateway_state).await
        } else {
            serve_http_connection(stream, fake_addr, entry, None, gateway_state).await
        }
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let control = crate::dependency::termination::ConnectionControl::new(&stream).unwrap();
    let mut client: Box<dyn TestStream> = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(state.ca().ca_cert_der()).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        Box::new(
            connector
                .connect(ServerName::try_from("dependency.test").unwrap(), stream)
                .await
                .unwrap(),
        )
    } else {
        Box::new(stream)
    };
    client
        .write_all(
            b"POST /timeout HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 4\r\n\r\nbody",
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    // Admission closes before the client finishes: the dependency must retain its original case.
    let drain_state = state.clone();
    let drain_case = case.clone();
    let drain = tokio::spawn(async move {
        drain_state
            .drain_active_case_dependencies(drain_case.id)
            .await
    });
    let mut probe = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(80), client.read(&mut probe))
            .await
            .is_err()
    );
    assert!(!drain.is_finished());
    if half_close {
        control.shutdown_write().unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(response.ends_with(b"ok"));
        tokio::time::timeout(Duration::from_secs(2), gateway)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    } else if cancel_engine {
        gateway.abort();
        assert!(gateway.await.unwrap_err().is_cancelled());
    } else {
        control.reset().unwrap();
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), gateway)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(drain.await.unwrap().is_none());
    state.recorder().flush_traffic().await.unwrap();
    state.recorder().publish_case(&case).await.unwrap();
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
    if half_close {
        assert_eq!(events[0]["outcome"], "response");
        assert_eq!(events[0]["response_status"], 200);
        assert!(events[0]["error"].is_null());
        assert!(state.active_case_invalidation(case.id).is_none());
    } else if cancel_engine {
        assert_eq!(events[0]["outcome"], "response");
        assert!(
            events[0]["error"]
                .as_str()
                .unwrap()
                .contains("without observed client termination")
        );
    } else {
        assert!(
            serde_json::from_value::<crate::DependencyExchangeOutcome>(
                events[0]["outcome"].clone()
            )
            .unwrap()
            .is_client_terminated()
        );
        assert!(events[0]["error"].is_null());
    }
    assert_eq!(events[0]["response_status"].is_null(), !half_close);
    assert!(events[0]["duration_ms"].as_u64().unwrap() >= 70);
    assert_eq!(events[0]["request_body"]["original_len"], 4);
    upstream_task.abort();
}
