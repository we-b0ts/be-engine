//! Quotas are checked after actual case ownership release, not file publication.
use super::*;
use std::net::SocketAddr;

async fn upstream(
    body: &'static str,
    requests: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..requests {
            let (mut socket, _) = listener.accept().await.unwrap();
            head(&mut socket).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    (address, task)
}

#[tokio::test]
async fn http_gateway_limits_published_cases_independently_by_case_pattern() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let (matched, matched_task) = upstream("matched", 3).await;
        let (fallback, fallback_task) = upstream("fallback", 2).await;
        let mut config = AppConfig::default();
        config.http_gateway.enabled = true;
        config.http_gateway.matched_upstream = format!("http://{matched}");
        config.http_gateway.fallback_upstream = format!("http://{fallback}");
        config.http_gateway.per_api_case_limits.default = 1;
        config
            .http_gateway
            .per_api_case_limits
            .overrides
            .insert("/record/override/*".into(), 2);
        config.http_gateway.rules = vec![HttpGatewayRuleConfig {
            name: Some("record-path".into()),
            methods: vec!["GET".into()],
            path_prefixes: vec!["/record/".into()],
            ..Default::default()
        }];
        config.http_gateway.case_path_patterns =
            vec!["/record/default/*".into(), "/record/override/*".into()];
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.case_dependency_post_response_window_ms = 0;
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let gateway = tokio::spawn(crate::gateway::http::run_with_listener(
            state.clone(),
            listener,
        ));
        for (path, expected, default_count, override_count) in [
            ("/record/default/one", "matched", 1, 0),
            ("/record/default/two", "fallback", 1, 0),
            ("/record/override/one", "matched", 1, 1),
            ("/record/override/two", "matched", 1, 2),
            ("/record/override/three", "fallback", 1, 2),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(
                    format!(
                        "GET {path} HTTP/1.1\r\nHost: source.test\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            assert!(response.contains(expected), "{path}: {response}");
            assert!(
                state
                    .inner
                    .active_cases
                    .wait_for_no_active_case(Duration::from_secs(2))
                    .await
            );
            let root = &state.recorder().run_dir;
            for (group, count) in [
                ("record-default-wildcard", default_count),
                ("record-override-wildcard", override_count),
            ] {
                let directory = root.join("apis").join(group);
                let actual = if directory.exists() {
                    std::fs::read_dir(directory).unwrap().count()
                } else {
                    0
                };
                assert_eq!(actual, count, "{path}: {group}");
            }
            let manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("recording-run.json")).unwrap())
                    .unwrap();
            assert_eq!(manifest["published_cases"], default_count + override_count);
            assert_eq!(manifest["failed_cases"], 0);
        }
        matched_task.await.unwrap();
        fallback_task.await.unwrap();
        gateway.abort();
    })
    .await
    .unwrap();
}
