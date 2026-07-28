use chrono::Utc;

use super::*;

fn http_dependency(authority: &str, uri: &str) -> RecorderEvent {
    let response = vec![b'x'; 314_066];
    RecorderEvent::HttpExchange(HttpExchangeEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        client_addr: None,
        scheme: "fake_ip_http".to_string(),
        method: "GET".to_string(),
        uri: uri.to_string(),
        authority: Some(authority.to_string()),
        request_headers: Default::default(),
        request_body: capture_body(&[], 1),
        response_status: Some(200),
        response_headers: Some(Default::default()),
        response_body: Some(capture_body(&response, response.len())),
        discovered_tcp_targets: Vec::new(),
        duration_ms: 10,
        error: None,
    })
}

#[tokio::test]
async fn background_http_enters_global_pool_but_not_case_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.traffic_jsonl = TrafficJsonlMode::Full;
    config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
        name: "config-refresh".to_string(),
        authorities: vec!["config.api.demo.test".to_string()],
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/1/config/service".to_string()],
        response_role: BackgroundDependencyResponseRole::Independent,
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
    }];
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.dns_mock.registry_path = temp.path().join("fake-dns.json");
    config.http_gateway.ready.enabled = false;
    let state = AppState::new(config).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();

    let background = http_dependency(
        "config.api.demo.test",
        "/1/config/service?action=lookup&group=reload.properties",
    );
    state.record_event(background);
    drop(guard);
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().finish_run().await.unwrap();

    let traffic = tokio::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert!(traffic.contains("config.api.demo.test"));
    assert!(traffic.contains("\"stored_len\":314066"));
    let dependencies =
        tokio::fs::read_to_string(state.recorder().case_dir(&case).join("dependencies.jsonl"))
            .await
            .unwrap();
    assert!(dependencies.is_empty());
    let global =
        tokio::fs::read_to_string(state.recorder().run_dir.join("global-dependencies.jsonl"))
            .await
            .unwrap();
    assert_eq!(global.lines().count(), 1);
    assert!(global.contains("\"global_dependency_reason\":\"background_rule\""));
    assert!(global.contains("\"global_dependency_phase\":\"runtime\""));
    assert!(global.contains("\"global_dependency_matched_by\":\"config-refresh\""));
}
