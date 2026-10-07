use super::*;
use std::path::Path;

const POLICY: &str = r#"version: 2
http:
  case_path_patterns: [/api/teams/*/skills]
  allowed_unused_http_hosts: [config.example]
process_owned_dependencies:
- protocol: http
  name: configuration_refresh
  authorities: [config.example]
  methods: [GET]
  path_prefixes: [/refresh]
  source_revision: abc1234
  source_evidence: test configuration refresh
"#;

fn options(path: &Path) -> OnlineRecordingOptions {
    OptionsCli::try_parse_from([
        "recording-online".as_ref(),
        "--advertise-url".as_ref(),
        "http://127.0.0.1:4080".as_ref(),
        "--source-traffic-policy".as_ref(),
        path.as_os_str(),
        "--case-limit".as_ref(),
        "2".as_ref(),
        "--".as_ref(),
        "true".as_ref(),
    ])
    .unwrap()
    .options
}

#[test]
fn standalone_policy_applies_overlays_without_api_filters() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source-traffic-policy.yaml");
    std::fs::write(&path, format!("{POLICY}http_response_rewrite:\n- name: sandbox.example\n  rules:\n  - path_pattern: GET /sandboxes/*\n    pointer: /base_url\n    source_evidence: source consumes this sandbox URL\n")).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions).unwrap();
    let config = options(&path).config().unwrap();
    assert_eq!(
        config.http_gateway.case_path_patterns,
        ["/api/teams/*/skills"]
    );
    assert_eq!(
        config.http_gateway.allowed_unused_http_hosts,
        ["config.example"]
    );
    assert_eq!(config.process_owned_dependencies.len(), 1);
    assert!(config.http_response_rewrite.is_enabled());
    assert_eq!(
        config.http_response_rewrite.rules[0].pointers,
        ["/base_url"]
    );
    assert_eq!(config.http_gateway.per_api_case_limits.default, 2);
    assert!(config.http_gateway.rules.is_empty());
    assert!(config.http_gateway.exclude_rules.is_empty());
    assert_eq!(
        config.recording.access_policy,
        crate::RecordingAccessPolicy::Unrestricted
    );
}

#[test]
fn explicitly_configured_missing_or_invalid_policy_fails_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source-traffic-policy.yaml");
    assert!(options(&path).config().is_err());
    assert!(options(temp.path()).config().is_err());
    for policy in [
        "version: [",
        "version: 99\n",
        "version: 2\nhttp:\n  case_path_patterns: wrong-type\n",
        "version: 2\nunknown_field: true\n",
        "version: 2\nhttp:\n  allowed_unused_http_hosts: ['https://config.example']\n",
        "version: 2\nbreeze_capture:\n- snapshot_dir: /missing-strategy\n  capture_resources: []\n",
    ] {
        std::fs::write(&path, policy).unwrap();
        assert!(
            options(&path).config().is_err(),
            "accepted invalid policy: {policy}"
        );
    }
}

#[test]
fn loaded_policy_groups_team_ids_and_shares_the_case_limit() {
    runtime().block_on(async {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source-traffic-policy.yaml");
        std::fs::write(&path, POLICY).unwrap();
        let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_address = source.local_addr().unwrap();
        let gateway_address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let mut options = options(&path);
        options.source_origin = format!("http://{source_address}");
        options.recorder_listen = gateway_address;
        options.data_root = temp.path().join("data");
        options.no_interception = true;
        let mut config = options.config().unwrap();
        // These synthetic requests contain no credentials and need no global test key.
        config.recording.encrypt_request_headers.clear();
        config.recording.case_dependency_post_response_window_ms = 0;
        // Pre-existing project state must be loaded, including its CA private key.
        let ca =
            crate::tls::MitmCa::load_or_generate(&config.tls.ca_cert_path, &config.tls.ca_key_path)
                .unwrap();
        let ca_pem = ca.ca_cert_pem().to_owned();
        let ca_key = std::fs::read(&config.tls.ca_key_path).unwrap();
        let ca_key_path = config.tls.ca_key_path.clone();
        let registry = crate::dns_mock::FakeDnsRegistry::load_or_new(
            &config.dns_mock.fake_cidr,
            Some(&config.dns_mock.registry_path),
            &[],
        )
        .unwrap();
        let alias = registry
            .register_raw_tcp_response_alias("existing.example", "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        registry.flush_if_dirty().await.unwrap();
        let state = crate::AppState::new(config).await.unwrap();
        assert_eq!(state.ca().ca_cert_pem(), ca_pem);
        assert_eq!(std::fs::read(ca_key_path).unwrap(), ca_key);
        assert_eq!(
            state
                .dns_registry()
                .get_response_alias_by_domain("existing.example")
                .await
                .unwrap()
                .fake_ip,
            alias.fake_ip
        );
        state.close_bootstrap("policy test ready").await.unwrap();
        let running = state.clone();
        let gateway =
            tokio::spawn(async move { crate::gateway::http::run(running).await.unwrap() });
        let source = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = source.accept().await.unwrap();
                read_request(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while tokio::net::TcpStream::connect(gateway_address)
                .await
                .is_err()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        for (request_path, expected_status) in [
            ("/api/teams/110467/skills", StatusCode::OK),
            ("/api/teams/122457/skills?view=all", StatusCode::OK),
            ("/api/teams/179584/skills", StatusCode::NOT_FOUND),
            ("/api/users/me/pet", StatusCode::OK),
        ] {
            let request = Request::builder()
                .uri(format!("http://{gateway_address}{request_path}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = tokio::time::timeout(Duration::from_secs(2), client.request(request))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), expected_status, "{request_path}");
            response.into_body().collect().await.unwrap();
        }
        source.await.unwrap();
        gateway.abort();
        let _ = gateway.await;
        state.recorder().finish_run().await.unwrap();
        let apis = state.recorder().run_dir.join("apis");
        let mut group_names = std::fs::read_dir(&apis)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        group_names.sort();
        assert_eq!(
            group_names,
            ["api-teams-wildcard-skills", "api-users-me-pet"]
        );
        let cases = std::fs::read_dir(apis.join("api-teams-wildcard-skills"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 2);
        for case in cases {
            let request: serde_json::Value =
                serde_json::from_slice(&std::fs::read(case.join("request.json")).unwrap()).unwrap();
            assert_eq!(request["api_pattern"], "/api/teams/*/skills");
        }
    });
}
