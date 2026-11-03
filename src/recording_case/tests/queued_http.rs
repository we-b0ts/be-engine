//! Real proxy exchanges cover either order of primary and async submission.
use super::*;
use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq)]
enum Timing {
    Before,
    After,
    Overlap,
}

#[tokio::test]
async fn queued_http_submission_completes_before_primary_response() {
    queued(Timing::Before).await;
}

#[tokio::test]
async fn queued_http_submission_starts_after_primary_response() {
    queued(Timing::After).await;
}

#[tokio::test]
async fn queued_http_submission_spans_primary_response() {
    queued(Timing::Overlap).await;
}

async fn queued(timing: Timing) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = upstream.local_addr().unwrap();
        let mut config = AppConfig::default();
        config.http_gateway.enabled = true;
        config.http_gateway.matched_upstream = format!("http://{}", source.local_addr().unwrap());
        config.http_gateway.request_timeout_ms = 2_000;
        config.http_gateway.rules = vec![HttpGatewayRuleConfig {
            methods: vec!["POST".into()], paths: vec!["/jobs".into()], ..Default::default()
        }];
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.case_dependency_post_response_window_ms = 0;
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        config.async_api.insert("POST /jobs".into(), serde_json::from_value(json!([
            {"when_response":{"/status":"queued"},"end":[{"http":{
                "method":"POST","endpoint":endpoint.to_string(),"path":"/submit"
            }}]},
            {"when_response":{"/status":"in_progress"},"end":[{"redis":{
                "operation":"DEL","key":"done:*","occurrence":2
            }}]}
        ])).unwrap());
        let state = AppState::new(config).await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(crate::proxy::http::run_with_listener(state.clone(), proxy));
        let (release, released) = tokio::sync::oneshot::channel();
        let (accepted, acceptance) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            head(&mut socket).await;
            let mut body = [0; 2];
            socket.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"{}");
            accepted.send(()).unwrap();
            if timing == Timing::Overlap { released.await.unwrap(); }
            socket.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        });
        let (start, started) = tokio::sync::oneshot::channel();
        let (case_sender, case_receiver) = tokio::sync::oneshot::channel();
        let source_state = state.clone();
        let worker = tokio::spawn(async move {
            let (mut socket, _) = source.accept().await.unwrap();
            head(&mut socket).await;
            let mut body = [0; 2];
            socket.read_exact(&mut body).await.unwrap();
            let case = source_state.capture_dependency_targets().cases[0].0.clone();
            case_sender.send(case).unwrap();
            let submission = async move {
                if timing == Timing::After {
                    started.await.unwrap();
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
                let mut client = TcpStream::connect(proxy_address).await.unwrap();
                client.write_all(format!("POST http://{endpoint}/submit HTTP/1.1\r\nHost: {endpoint}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 202"));
            };
            let mut submission = Some(tokio::spawn(submission));
            if timing == Timing::Before {
                submission.take().unwrap().await.unwrap();
            } else if timing == Timing::Overlap {
                acceptance.await.unwrap();
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"status\":\"queued\"}").await.unwrap();
            socket.shutdown().await.unwrap();
            if let Some(submission) = submission { submission.await.unwrap(); }
        });
        let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway.local_addr().unwrap();
        let gateway_task = tokio::spawn(crate::gateway::http::run_with_listener(state.clone(), gateway));
        let mut client = TcpStream::connect(gateway_address).await.unwrap();
        client.write_all(b"POST /jobs HTTP/1.1\r\nHost: source.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        let case = case_receiver.await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_millis(750), client.read_to_end(&mut response)).await.unwrap().unwrap();
        assert!(response.ends_with(br#"{"status":"queued"}"#));
        if timing != Timing::Before {
            assert!(!state.recorder().case_dir(&case).exists());
        }
        if timing == Timing::After { start.send(()).unwrap(); }
        if timing == Timing::Overlap { release.send(()).unwrap(); }
        worker.await.unwrap();
        server.await.unwrap();
        assert!(state.inner.active_cases.wait_for_no_active_case(Duration::from_secs(2)).await);
        let directory = state.recorder().case_dir(&case);
        let report: Value = serde_json::from_slice(&tokio::fs::read(directory.join("async-api-observation.json")).await.unwrap()).unwrap();
        assert_eq!(report["end_reason"], "resource");
        assert_eq!(report["scenario_index"], 0);
        let receipt = crate::policy::AsyncRuleProvenance::selected(
            "POST /jobs", &state.config().async_api["POST /jobs"], 0
        ).unwrap();
        assert_eq!(report["policy_provenance"], serde_json::to_value(receipt).unwrap());
        assert_eq!(report["inventory_complete"], true);
        assert_eq!(report["completed_refs"].as_array().unwrap().len(), 1);
        assert!(!state.inner.active_cases.is_quiescing());
        let dependencies = crate::recorder::test_io::read_to_string(directory.join("dependencies.jsonl")).await.unwrap();
        let dependencies = dependencies.lines().map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0]["method"], "POST");
        assert_eq!(dependencies[0]["response_status"], 202);
        gateway_task.abort();
        proxy_task.abort();
    }).await.unwrap();
}
