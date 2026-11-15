use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn consumes_http_timeout_only_after_client_close() {
    replay_timeout(false, 120, 120, false).await;
}

#[tokio::test]
async fn consumes_https_timeout_only_after_client_close() {
    replay_timeout(true, 120, 120, false).await;
}

#[tokio::test]
async fn premature_http_client_close_remains_dirty() {
    replay_timeout(false, 1000, 80, false).await;
}

trait TestStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestStream for T {}

fn dependency(tls: bool, duration: u64) -> Value {
    serde_json::json!({
        "event_type":"http_exchange", "scheme":if tls { "https" } else { "http" },
        "method":"POST", "uri":"/timeout", "authority":"dependency.test",
        "request_body":{"encoding":"utf8","truncated":false,"data":"body"},
        "response_status":null,"response_headers":null,"response_body":null,
        "error":null,"outcome":"client_terminated","duration_ms":duration,
    })
}

async fn replay_timeout(tls: bool, recorded: u64, observed: u64, fin_first: bool) {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        dependency(tls, recorded).to_string(),
    )
    .await
    .unwrap();
    let (addr, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay(&case_dir, Vec::new()).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let control = crate::dependency::termination::ConnectionControl::new(&stream).unwrap();
    let mut client: Box<dyn TestStream> = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(runtime.ca.ca_cert_der()).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        Box::new(
            connector
                .connect(
                    rustls::pki_types::ServerName::try_from("dependency.test").unwrap(),
                    stream,
                )
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
    if fin_first {
        control.shutdown_write().unwrap();
    }
    let mut probe = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(observed), client.read(&mut probe))
            .await
            .is_err()
    );
    {
        let state = runtime.state.lock().await;
        assert_eq!(state.protocols.http_events.matched_count, 0);
        assert!(!state.protocols.http_exchanges[0].status.is_consumed());
    }
    control.reset().unwrap();
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = runtime.state.lock().await;
            if state.protocols.http_exchanges[0].status
                != ReplayExchangeStatus::AwaitingClientTermination
            {
                break;
            }
            drop(state);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    assert!(state.protocols.http_events.unmatched.is_empty());
    if recorded == observed && !fin_first {
        assert_eq!(state.protocols.http_events.matched_count, 1);
        assert!(state.protocols.http_events.unsupported.is_empty());
        assert!(state.protocols.http_exchanges[0].status.is_consumed());
    } else {
        assert_eq!(state.protocols.http_events.matched_count, 0);
        if fin_first {
            assert!(
                state.protocols.http_events.unsupported[0]
                    .reason
                    .contains("timing window")
            );
        } else {
            assert!(
                state.protocols.http_events.unsupported[0]
                    .reason
                    .contains("too early")
            );
        }
        assert_eq!(
            state.protocols.http_exchanges[0].status,
            ReplayExchangeStatus::Failed
        );
    }
    task.abort();
}

#[tokio::test]
async fn http_client_that_never_closes_remains_dirty() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        dependency(false, 20).to_string(),
    )
    .await
    .unwrap();
    let (addr, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay(&case_dir, Vec::new()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(
            b"POST /timeout HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 4\r\n\r\nbody",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(1200),
            client.read_to_end(&mut response)
        )
        .await
        .is_err(),
        "validation timeout must not manufacture peer EOF"
    );
    assert!(response.is_empty());
    let state = runtime.state.lock().await;
    assert_eq!(state.protocols.http_events.matched_count, 0);
    assert_eq!(
        state.protocols.http_exchanges[0].status,
        ReplayExchangeStatus::Failed
    );
    assert!(!state.protocols.http_events.unsupported.is_empty());
    task.abort();
}

#[test]
fn rejects_ambiguous_http_termination_evidence() {
    let mut value = dependency(false, 80);
    for field in ["duration_ms", "error", "response_status", "response_body"] {
        let original = value[field].clone();
        value[field] = match field {
            "duration_ms" => Value::Null,
            "error" => Value::String("upstream error".into()),
            "response_status" => Value::from(200),
            _ => serde_json::json!({"encoding":"utf8","truncated":false,"data":"partial"}),
        };
        let record = serde_json::from_value(value.clone()).unwrap();
        assert!(
            validate_record(&record).is_err(),
            "accepted ambiguous {field}"
        );
        value[field] = original;
    }
}

#[tokio::test]
async fn identical_http_retries_consume_separate_timeout_exchanges() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("case");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    let record = dependency(false, 80).to_string();
    tokio::fs::write(
        case_dir.join("dependencies.jsonl"),
        format!("{record}\n{record}\n"),
    )
    .await
    .unwrap();
    let (addr, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay(&case_dir, Vec::new()).await;
    let request = b"POST /timeout HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";
    for _ in 0..2 {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut probe = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(80), client.read(&mut probe))
                .await
                .is_err()
        );
        crate::dependency::termination::ConnectionControl::new(&client)
            .unwrap()
            .reset()
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .protocols
                .http_events
                .matched_count
                == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut extra = TcpStream::connect(addr).await.unwrap();
    extra.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), extra.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&response).contains("502"));
    let state = runtime.state.lock().await;
    assert_eq!(state.protocols.http_events.matched_count, 2);
    assert_eq!(state.protocols.http_events.unmatched.len(), 1);
    assert!(
        state
            .protocols
            .http_exchanges
            .iter()
            .all(|exchange| exchange.status.is_consumed())
    );
    task.abort();
}

#[tokio::test]
async fn replay_http_fin_then_unobserved_reset_cannot_certify_cancellation() {
    replay_timeout(false, 120, 120, true).await;
}
#[tokio::test]
async fn replay_https_fin_then_unobserved_reset_cannot_certify_cancellation() {
    replay_timeout(true, 120, 120, true).await;
}

#[tokio::test]
async fn replay_http_client_fin_preserves_delayed_response() {
    replay_half_close(false).await;
}
#[tokio::test]
async fn replay_https_client_fin_preserves_delayed_response() {
    replay_half_close(true).await;
}

async fn replay_half_close(tls: bool) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let mut record = dependency(tls, 120);
    record["outcome"] = Value::from("response");
    record["response_status"] = Value::from(200);
    record["response_headers"] = serde_json::json!({"content-type":["text/event-stream"]});
    record["response_stream"] = serde_json::json!({"version":1,"headers_ms":80,"chunks":[{"at_ms":120,"start":0,"end":2}],"end_ms":160,"complete":true});
    record["response_body"] = serde_json::json!({"encoding":"utf8","truncated":false,"data":"ok"});
    tokio::fs::write(case.join("dependencies.jsonl"), record.to_string())
        .await
        .unwrap();
    let (address, runtime, task) =
        crate::protocols::replay::http::tests::spawn_http_replay(&case, Vec::new()).await;
    let socket = TcpStream::connect(address).await.unwrap();
    let control = crate::dependency::termination::ConnectionControl::new(&socket).unwrap();
    let mut client: Box<dyn TestStream> = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(runtime.ca.ca_cert_der()).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        Box::new(
            connector
                .connect(
                    rustls::pki_types::ServerName::try_from("dependency.test").unwrap(),
                    socket,
                )
                .await
                .unwrap(),
        )
    } else {
        Box::new(socket)
    };
    client.write_all(b"POST /timeout HTTP/1.1\r\nHost: dependency.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody").await.unwrap();
    control.shutdown_write().unwrap();
    let started = tokio::time::Instant::now();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(80));
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"2\r\nok\r\n0\r\n\r\n"));
    let state = runtime.state.lock().await;
    assert_eq!(state.protocols.http_events.matched_count, 1);
    assert!(state.protocols.http_events.unsupported.is_empty());
    task.abort();
}
