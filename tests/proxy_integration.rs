use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use traffic_recorder_proxy::{
    AppConfig, HttpGatewayReadyConfig, HttpGatewayRuleConfig, HttpResponseRewriteConfig,
    HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig, MysqlRouteConfig,
    RecordingAccessPolicy, VerifiedApiExclude, VerifiedApiExcludesConfig,
};

#[tokio::test]
async fn records_http_proxy_exchange() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .unwrap();
    });

    let proxy_addr = free_addr();
    let mut config = AppConfig::default();
    config.http.enabled = true;
    config.http.listen = proxy_addr;
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(proxy_addr).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "GET http://{upstream_addr}/hello HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("hello"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let jsonl = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"http_exchange""#));
    assert!(jsonl.contains(r#""method":"GET""#));
}

#[tokio::test]
async fn recording_policy_blocks_http_write_before_upstream_and_audits_it() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let proxy_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.enabled = true;
    config.http.listen = proxy_addr;
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(proxy_addr).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!(
        "POST http://{upstream_addr}/write HTTP/1.1\r\nHost: {upstream_addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("403 Forbidden"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let jsonl = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"readonly_rejection""#));
    assert!(jsonl.contains(r#""operation_class":"write""#));
    assert!(!run_dir.join("bootstrap-dependencies.jsonl").exists());

    let report: Value = serde_json::from_str(
        &tokio::fs::read_to_string(run_dir.join("recording-run.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["access_policy"], "block_known_writes");
}

#[tokio::test]
async fn recording_policy_blocks_http_gateway_write_before_case_registration() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{}", matched.local_addr().unwrap());
    config.http_gateway.fallback_upstream = format!("http://{}", fallback.local_addr().unwrap());
    config.http_gateway.exclude_rules = vec![HttpGatewayRuleConfig {
        name: Some("exclude-delete".to_string()),
        methods: vec!["DELETE".to_string()],
        ..Default::default()
    }];
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.access_policy = RecordingAccessPolicy::BlockKnownWrites;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let mut client = TcpStream::connect(gateway_addr).await.unwrap();
    client
        .write_all(b"DELETE /items/1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).contains("403 Forbidden"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), matched.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), fallback.accept())
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();
    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    assert!(!run_dir.join("default").exists());
    let jsonl = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""protocol":"http_gateway""#));
}

#[tokio::test]
async fn http_gateway_applies_manual_and_verified_excludes_before_recording() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream = spawn_http_response_upstream("matched", 1).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 3).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("record-path".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        ..Default::default()
    }];
    config.http_gateway.exclude_rules = vec![HttpGatewayRuleConfig {
        name: Some("exclude-private".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/private".to_string()],
        ..Default::default()
    }];
    config.http_gateway.verified_excludes = VerifiedApiExcludesConfig {
        consecutive_successes: 3,
        apis: vec![VerifiedApiExclude {
            rule: "record-path".to_string(),
            method: "GET".to_string(),
            path_pattern: "/record/verified/*".to_string(),
        }],
    };
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let matched_response = raw_http_get(gateway_addr, "/record").await;
    assert!(matched_response.contains("matched"));
    let excluded_response = raw_http_get(gateway_addr, "/record/private").await;
    assert!(excluded_response.contains("fallback"));
    let verified_response = raw_http_get(gateway_addr, "/record/verified/123").await;
    assert!(verified_response.contains("fallback"));
    let fallback_response = raw_http_get(gateway_addr, "/recording/two").await;
    assert!(fallback_response.contains("fallback"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let jsonl = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"http_exchange""#));
    assert!(jsonl.contains("/record"));
    assert!(!jsonl.contains("/record/private"));
    assert!(!jsonl.contains("/record/verified/123"));
    assert!(!jsonl.contains("/recording/two"));
}

#[tokio::test]
async fn http_gateway_falls_back_before_ready() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream = spawn_http_response_upstream("matched", 2).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.ready = HttpGatewayReadyConfig {
        enabled: true,
        path: "/ready".to_string(),
        success_status: 204,
        interval_ms: 1000,
    };
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("record-path".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        ..Default::default()
    }];
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let response = raw_http_get(gateway_addr, "/record/one").await;
    assert!(response.contains("fallback"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    assert!(!run_dir.join("record-path").exists());
}

#[tokio::test]
async fn http_gateway_allows_only_one_active_matched_case() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream =
        spawn_delayed_http_response_upstream("matched", 1, Duration::from_millis(200)).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("record-path".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/record/".to_string()],
        ..Default::default()
    }];
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let first = tokio::spawn(raw_http_get(gateway_addr, "/record/one"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second_response = raw_http_get(gateway_addr, "/record/two").await;
    assert!(second_response.contains("fallback"));
    let first_response = first.await.unwrap();
    assert!(first_response.contains("matched"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let rule_dir = run_dir.join("record-path");
    let uri_group_dirs = std::fs::read_dir(&rule_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(uri_group_dirs.len(), 1);
    assert_eq!(
        uri_group_dirs[0].file_name().unwrap().to_str().unwrap(),
        "record-one"
    );
    let case_dirs = std::fs::read_dir(&uri_group_dirs[0])
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(case_dirs.len(), 1);
    assert!(case_dirs[0].join("request.json").exists());
}

#[tokio::test]
async fn http_gateway_writes_case_files_and_decodes_gzip_response() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream = spawn_http_gzip_response_upstream(r#"{"ok":true}"#).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api/".to_string()],
        ..Default::default()
    }];
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let response = raw_http_get(gateway_addr, "/api/users/list").await;
    assert!(response.contains("Content-Encoding: gzip"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let rule_dir = run_dir.join("api/api-users-list");
    let case_dirs = std::fs::read_dir(&rule_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(case_dirs.len(), 1);
    let case_dir = &case_dirs[0];

    let request_json = std::fs::read_to_string(case_dir.join("request.json")).unwrap();
    assert!(request_json.contains(r#""uri": "/api/users/list""#));

    let response_json = std::fs::read_to_string(case_dir.join("expected-response.json")).unwrap();
    let response: Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response["status"], 200);
    assert_eq!(response["body"]["encoding"], "utf8");
    assert_eq!(response["body"]["decoded"], true);
    assert_eq!(response["body"]["content_encoding"], "gzip");
    assert_eq!(response["body"]["data"], r#"{"ok":true}"#);
}

#[tokio::test]
async fn http_gateway_rewrites_pluto_eci_kubeconfig_and_registers_alias() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let cluster_id = "c142fe56e07d04a749c1630fb5f1b680b";
    let original_ip = "182.92.232.38";
    let body = serde_json::json!({
        "config": format!(
            "apiVersion: v1\nclusters:\n- cluster:\n    server: https://{original_ip}:6443\n    certificate-authority-data: REDACTED\n  name: kubernetes\nusers:\n- name: admin\n  user:\n    client-key-data: REDACTED\n"
        ),
        "expiration": "2027-01-01T00:00:00Z"
    })
    .to_string();
    let matched_upstream = spawn_http_json_response_upstream(body).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();
    let proxy_listen = free_addr();
    let proxy_started = temp.path().join("proxy-started");
    let captured_kubeconfig = temp.path().join("captured-kubeconfig");
    let fake_kubectl = temp.path().join("fake-kubectl");
    std::fs::write(
        &fake_kubectl,
        format!(
            "#!/bin/sh\nkubeconfig=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--kubeconfig\" ]; then\n    shift\n    kubeconfig=\"$1\"\n  fi\n  shift\ndone\ncp \"$kubeconfig\" '{}'\ntouch '{}'\nexec sleep 30\n",
            captured_kubeconfig.display(),
            proxy_started.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_kubectl, std::fs::Permissions::from_mode(0o700)).unwrap();
    let proxy_listener = tokio::spawn(async move {
        while !proxy_started.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let listener = TcpListener::bind(proxy_listen).await.unwrap();
        loop {
            let _ = listener.accept().await.unwrap();
        }
    });

    let mut config = AppConfig::default();
    config.dns_mock.enabled = true;
    config.dns_mock.listen = free_udp_addr();
    config.tcp_gateway.enabled = true;
    config.tcp_gateway.listen = free_addr();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api/".to_string()],
        ..Default::default()
    }];
    config.http_response_rewrite = HttpResponseRewriteConfig {
        enabled: true,
        rules: vec![HttpResponseRewriteRuleConfig {
            name: "pluto-kubeconfig".to_string(),
            authorities: vec!["cs.aliyuncs.com".to_string()],
            methods: vec!["GET".to_string()],
            path: format!("/api/v2/k8s/{cluster_id}/user_config"),
            status_codes: vec![200],
            content_types: vec!["application/json".to_string()],
            plugin: HttpResponseRewritePluginConfig::PlutoEciKubeconfig {
                kubectl_binary: fake_kubectl.to_string_lossy().into_owned(),
                proxy_listen,
            },
        }],
    };
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let state_for_assertion = state.clone();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let path = format!("/api/v2/k8s/{cluster_id}/user_config");
    let response = raw_http_get_with_host(gateway_addr, &path, "cs.aliyuncs.com").await;
    let alias = format!("k8s-{cluster_id}.pluto-eci.trp.test");
    assert!(response.contains(&format!("server: https://{alias}:{}", proxy_listen.port())));
    assert!(!response.contains(original_ip));
    assert!(!response.to_ascii_lowercase().contains("etag:"));
    let response_payload: Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    let response_kubeconfig: serde_yaml::Value =
        serde_yaml::from_str(response_payload["config"].as_str().unwrap()).unwrap();
    let rewritten_ca = response_kubeconfig["clusters"][0]["cluster"]["certificate-authority-data"]
        .as_str()
        .unwrap();
    assert_eq!(
        STANDARD.decode(rewritten_ca).unwrap(),
        state_for_assertion.ca().ca_cert_pem().as_bytes()
    );
    let proxy_kubeconfig = std::fs::read_to_string(&captured_kubeconfig).unwrap();
    assert!(proxy_kubeconfig.contains("server: https://182.92.232.38:6443"));
    assert!(proxy_kubeconfig.contains("client-key-data: REDACTED"));

    let entry = state_for_assertion
        .dns_registry()
        .get_response_alias_by_domain(&alias)
        .await
        .unwrap();
    assert_eq!(entry.real_ips, vec![Ipv4Addr::LOCALHOST]);
    assert_eq!(
        entry.upstream_authority.as_deref(),
        Some(proxy_listen.to_string().as_str())
    );
    assert_eq!(
        entry.upstream_protocol,
        Some(traffic_recorder_proxy::FakeDnsUpstreamProtocol::Http)
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();
    proxy_listener.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let rule_dir = run_dir.join(format!("api/api-v2-k8s-{cluster_id}-user_config"));
    let case_dir = std::fs::read_dir(rule_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(case_dir.join("expected-response.json")).unwrap(),
    )
    .unwrap();
    let recorded_body: Value =
        serde_json::from_str(expected["body"]["data"].as_str().unwrap()).unwrap();
    assert!(
        recorded_body["config"]
            .as_str()
            .unwrap()
            .contains(&format!("server: https://{alias}:{}", proxy_listen.port()))
    );
}

#[tokio::test]
async fn http_gateway_keeps_truncated_case_out_of_published_recordings() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let matched_upstream = spawn_http_response_upstream(r#"{"ok":true,"items":[1,2,3]}"#, 1).await;
    let fallback_upstream = spawn_http_response_upstream("fallback", 1).await;
    let gateway_addr = free_addr();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched_upstream}");
    config.http_gateway.fallback_upstream = format!("http://{fallback_upstream}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/api/".to_string()],
        ..Default::default()
    }];
    config.mysql.enabled = false;
    config.recording.max_body_bytes = 8;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(gateway_addr).await;

    let response = raw_http_get(gateway_addr, "/api/users/list").await;
    assert!(response.contains(r#"{"ok":true"#));

    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let published_group = run_dir.join("api/api-users-list");
    assert!(
        !published_group.exists()
            || std::fs::read_dir(&published_group)
                .unwrap()
                .next()
                .is_none()
    );

    let failed_group = run_dir.join("failed/api/api-users-list");
    let failed_cases = std::fs::read_dir(&failed_group)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(failed_cases.len(), 1);
    let failed_case = &failed_cases[0];
    assert!(failed_case.join("request.json.partial").exists());
    assert!(
        failed_case
            .join("expected-response.json.truncated")
            .exists()
    );
    assert!(!failed_case.join("request.json").exists());
    assert!(!failed_case.join("expected-response.json").exists());

    let error_raw = std::fs::read_to_string(failed_case.join("recording-error.json")).unwrap();
    assert!(error_raw.contains("expected_response_body_truncated"));
    let report_raw = std::fs::read_to_string(run_dir.join("recording-run.json")).unwrap();
    let report: Value = serde_json::from_str(&report_raw).unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["published_cases"], 0);
    assert_eq!(report["failed_cases"], 1);
    let errors_raw = std::fs::read_to_string(run_dir.join("errors.jsonl")).unwrap();
    assert!(errors_raw.contains("expected_response_body_truncated"));
}

#[tokio::test]
async fn records_and_rejects_mysql_tls_request() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = upstream.accept().await.unwrap();
            stream
                .write_all(&mysql_packet(0, mysql_handshake_payload().as_slice()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let proxy_addr = free_addr();
    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.mysql.enabled = true;
    config.mysql.listen = proxy_addr;
    config.mysql.upstream = upstream_addr.to_string();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(proxy_addr).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await.unwrap();
    let payload_len =
        header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0_u8; payload_len];
    client.read_exact(&mut payload).await.unwrap();

    let mut ssl_request = vec![0_u8; 32];
    ssl_request[0..4].copy_from_slice(&0x0000_8800_u32.to_le_bytes());
    client
        .write_all(&mysql_packet(1, ssl_request.as_slice()))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.abort();

    let run_dir = only_recording_run_dir(&temp.path().join("recordings"));
    let jsonl = tokio::fs::read_to_string(run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(jsonl.contains(r#""event_type":"mysql_tls_rejected""#));
}

#[tokio::test]
async fn supports_multiple_mysql_routes_on_same_port_with_different_ips() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let temp = tempdir().unwrap();
    let master_upstream = spawn_mysql_handshake_upstream(1).await;
    let slave_upstream = spawn_mysql_handshake_upstream(1).await;
    let (master_listen, slave_listen) = free_same_port_loopback_pair();

    let mut config = AppConfig::default();
    config.http.listen = free_addr();
    config.mysql.enabled = true;
    config.mysql.routes = vec![
        MysqlRouteConfig {
            name: Some("master".to_string()),
            listen: master_listen,
            upstream: master_upstream.to_string(),
        },
        MysqlRouteConfig {
            name: Some("slave".to_string()),
            listen: slave_listen,
            upstream: slave_upstream.to_string(),
        },
    ];
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");

    let state = traffic_recorder_proxy::AppState::new(config).await.unwrap();
    let handle = tokio::spawn(async move { state.run().await });
    wait_for_port(master_listen).await;
    wait_for_port(slave_listen).await;
    handle.abort();
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn free_udp_addr() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn free_same_port_loopback_pair() -> (SocketAddr, SocketAddr) {
    for _ in 0..100 {
        let port = free_addr().port();
        let master = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port);
        let slave = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), port);
        let Ok(master_probe) = std::net::TcpListener::bind(master) else {
            continue;
        };
        let Ok(slave_probe) = std::net::TcpListener::bind(slave) else {
            continue;
        };
        drop(master_probe);
        drop(slave_probe);
        return (master, slave);
    }
    panic!("failed to find a free same-port loopback pair");
}

async fn spawn_http_response_upstream(body: &'static str, accept_count: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..accept_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    addr
}

async fn spawn_http_json_response_upstream(body: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=utf-8\r\nContent-Length: {}\r\nETag: original\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
}

async fn spawn_delayed_http_response_upstream(
    body: &'static str,
    accept_count: usize,
    delay: Duration,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..accept_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap();
            tokio::time::sleep(delay).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    addr
}

async fn spawn_http_gzip_response_upstream(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut encoder, body.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 2048];
        let _ = stream.read(&mut buf).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            compressed.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&compressed).await.unwrap();
    });
    addr
}

async fn spawn_mysql_handshake_upstream(accept_count: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..accept_count {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(&mysql_packet(0, mysql_handshake_payload().as_slice()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    addr
}

async fn raw_http_get(addr: SocketAddr, path: &str) -> String {
    raw_http_get_with_host(addr, path, "example.com").await
}

async fn raw_http_get_with_host(addr: SocketAddr, path: &str, host: &str) -> String {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).to_string()
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("port {addr} did not open");
}

fn only_recording_run_dir(recordings_dir: &Path) -> PathBuf {
    let run_dirs = std::fs::read_dir(recordings_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(run_dirs.len(), 1);
    run_dirs[0].clone()
}

fn mysql_packet(sequence_id: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.push((len & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(sequence_id);
    out.extend_from_slice(payload);
    out
}

fn mysql_handshake_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x0a);
    payload.extend_from_slice(b"8.0.0-test\0");
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(b"abcdefgh");
    payload.push(0);
    payload.extend_from_slice(&0xffff_u16.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&0xffff_u16.to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0_u8; 10]);
    payload.extend_from_slice(b"ijklmnopqrstuvwxyz\0");
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}
