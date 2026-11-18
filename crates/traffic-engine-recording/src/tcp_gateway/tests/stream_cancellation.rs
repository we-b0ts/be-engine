//! Real TLS clients close a dependency without manufacturing HTTP body EOF.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn https_dependency_reset_retains_a_flushed_response_prefix() {
    timeout(Duration::from_secs(8), capture(false))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Python with httpx; set TRAFFIC_E2E_TEST_PYTHON to its interpreter"]
async fn httpx_https_dependency_close_records_termination_or_explicit_capture_diagnosis() {
    timeout(Duration::from_secs(10), capture(true))
        .await
        .unwrap();
}

async fn capture(httpx: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = crate::AppState::new(config).await.unwrap();
    let case = crate::recorder::CaseContext {
        id: uuid::Uuid::new_v4(),
        rule_name: "tls-cancel".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let tls_config = state.ca().server_config_for_host("localhost").unwrap();
    let upstream = tokio::spawn(async move {
        let (socket, _) = upstream.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(tls_config).accept(socket).await.unwrap();
        read_head(&mut tls).await;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        if httpx {
            // A graceful httpx close can be only FIN. More real data exposes
            // the resulting write failure without treating FIN as cancellation.
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                if tls.write_all(b"c\r\ndata: more\n\n\r\n").await.is_err()
                    || tls.flush().await.is_err()
                {
                    break;
                }
            }
        } else {
            let _ = tls.read_to_end(&mut Vec::new()).await;
        }
    });
    let entry = FakeDnsEntry {
        domain: "localhost".into(),
        fake_ip: Ipv4Addr::new(198, 19, 0, 1),
        real_ips: vec![Ipv4Addr::LOCALHOST],
        response_alias: false,
        upstream_authority: None,
        upstream_protocol: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let fake_address = SocketAddr::new(IpAddr::V4(entry.fake_ip), upstream_address.port());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serving = state.clone();
    let gateway = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        let _ = serve_https_mitm_connection(
            socket,
            fake_address,
            entry,
            Some(peer.to_string()),
            serving,
        )
        .await;
    });
    if httpx {
        let python =
            std::env::var_os("TRAFFIC_E2E_TEST_PYTHON").unwrap_or_else(|| "python3".into());
        let output = tokio::process::Command::new(python)
            .args([
                "-c",
                HTTPX_CLIENT,
                &format!("https://localhost:{}/stream", address.port()),
            ])
            .arg(temp.path().join("ca.pem"))
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        let socket = TcpStream::connect(address).await.unwrap();
        let control = crate::dependency::termination::ConnectionControl::new(&socket).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(state.ca().ca_cert_der()).unwrap();
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut tls = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .unwrap();
        tls.write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        tls.flush().await.unwrap();
        read_head(&mut tls).await;
        let mut chunk = [0; 18];
        tls.read_exact(&mut chunk).await.unwrap();
        assert_eq!(&chunk[3..], b"data: first\n\n\r\n");
        assert_eq!(
            usize::from_str_radix(std::str::from_utf8(&chunk[..1]).unwrap(), 16).unwrap(),
            13
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        control.reset().unwrap();
    }
    gateway.await.unwrap();
    upstream.await.unwrap();
    assert!(
        state
            .drain_active_case_dependencies(case.id)
            .await
            .is_none()
    );
    let staging = state.recorder().case_staging_dir(&case);
    let _ = state
        .recorder()
        .case_dependency_safety_issue(&case)
        .await
        .unwrap();
    let raw = crate::recorder::test_io::read_to_string(staging.join("dependencies.jsonl"))
        .await
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(event["response_status"], 200);
    assert_eq!(event["response_body"]["truncated"], false);
    if let Some(failure) = state.active_case_invalidation(case.id) {
        assert!(
            httpx,
            "an independently observed reset should complete capture: {failure:?}"
        );
        assert_eq!(failure.reason, "http_stream_capture_incomplete");
        let diagnosis = failure
            .context
            .unwrap()
            .native
            .remove("http_stream")
            .unwrap();
        assert_eq!(diagnosis["exchange_id"], event["id"]);
        assert_eq!(diagnosis["client"]["engine_stopped"], false);
        assert!(
            !diagnosis["client"]["client_first"].is_null()
                || !diagnosis["client"]["io_errors"]
                    .as_array()
                    .unwrap()
                    .is_empty()
        );
        assert_eq!(event["response_stream"]["complete"], false);
    } else {
        let outcome: crate::DependencyExchangeOutcome =
            serde_json::from_value(event["outcome"].clone()).unwrap();
        assert!(
            outcome.is_client_terminated(),
            "close must not become response EOF"
        );
        assert_eq!(event["response_stream"]["complete"], true);
    }
}

async fn read_head<T: tokio::io::AsyncRead + Unpin>(socket: &mut T) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
}

const HTTPX_CLIENT: &str = r#"
import asyncio, httpx, ssl, sys
async def main():
    context = ssl.create_default_context(cafile=sys.argv[2])
    async with httpx.AsyncClient(verify=context, trust_env=False, timeout=3) as client:
        async with client.stream('GET', sys.argv[1]) as response:
            assert response.status_code == 200
            async for chunk in response.aiter_raw():
                assert chunk
                break
asyncio.run(main())
"#;
