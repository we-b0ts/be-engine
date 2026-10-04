use chrono::Utc;

use super::*;

fn case_limit_test_config(temp: &tempfile::TempDir) -> AppConfig {
    let mut config = AppConfig::default();
    config.http.enabled = false;
    config.dns_mock.enabled = false;
    config.tcp_gateway.enabled = false;
    config.udp_gateway.enabled = false;
    config.http_gateway.enabled = false;
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.http_gateway.per_api_case_limits.default = 1;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.dns_mock.registry_path = temp.path().join("fake-dns.json");
    config
}

#[tokio::test]
async fn explicit_api_case_limit_stops_and_finalizes_the_recorder_runtime() {
    let temp = tempfile::tempdir().unwrap();
    let config = case_limit_test_config(&temp);
    let api = "GET /api/users/*".parse::<RecordingApi>().unwrap();
    let state = AppState::new_with_recording_apis(config, None, vec![api])
        .await
        .unwrap();
    let runtime = tokio::spawn(state.clone().run());

    state
        .recorder()
        .publish_case_for_api(
            &CaseContext {
                id: Uuid::new_v4(),
                rule_name: "http-rule".to_string(),
                uri_group: Some("api-users-wildcard".to_string()),
            },
            Some("GET /api/users/*"),
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), runtime)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let report: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(state.recorder().run_dir.join("recording-run.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["status"], "completed");
    assert_eq!(report["published_cases"], 1);
    assert_eq!(report["completion_reason"], "per_api_case_limit_reached");
}

#[tokio::test(start_paused = true)]
async fn preflight_case_limit_keeps_the_runtime_alive_for_the_fixed_grace() {
    let temp = tempfile::tempdir().unwrap();
    let config = case_limit_test_config(&temp);
    let api = "GET /api/users/*".parse::<RecordingApi>().unwrap();
    let state = AppState::new_with_recording_options(
        config,
        None,
        vec![api],
        None,
        Some(PreflightProbeKind::JavaTruststore),
    )
    .await
    .unwrap();
    let runtime = tokio::spawn(state.clone().run());

    state
        .recorder()
        .publish_case_for_api(
            &CaseContext {
                id: Uuid::new_v4(),
                rule_name: "http-rule".to_string(),
                uri_group: Some("api-users-wildcard".to_string()),
            },
            Some("GET /api/users/*"),
        )
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert!(!runtime.is_finished());

    tokio::time::advance(std::time::Duration::from_secs(14)).await;
    tokio::task::yield_now().await;
    assert!(!runtime.is_finished());

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    runtime.await.unwrap().unwrap();
}

fn http_dependency(authority: &str, uri: &str) -> RecorderEvent {
    let response = vec![b'x'; 314_066];
    RecorderEvent::HttpExchange(HttpExchangeEvent {
        request_started_at: Utc::now(),
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

fn preflight_probe_dependency(user_agent: &str) -> RecorderEvent {
    let mut event = http_dependency("demo.test:443", "/");
    let RecorderEvent::HttpExchange(exchange) = &mut event else {
        unreachable!();
    };
    exchange.scheme = "fake_ip_https".to_string();
    exchange
        .request_headers
        .insert("user-agent".to_string(), vec![user_agent.to_string()]);
    exchange.request_headers.insert(
        crate::network_probe::ORIGIN_HEADER.to_string(),
        vec![crate::network_probe::SOURCE_ORIGIN.to_string()],
    );
    event
}

#[tokio::test]
async fn preflight_probe_publishes_one_exact_global_dependency() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.dns_mock.registry_path = temp.path().join("fake-dns.json");
    let state = AppState::new_with_recording_options(
        config,
        None,
        Vec::new(),
        None,
        Some(PreflightProbeKind::JavaTruststore),
    )
    .await
    .unwrap();

    state.record_event(preflight_probe_dependency(
        crate::network_probe::JAVA_USER_AGENT,
    ));
    state.record_event(preflight_probe_dependency(
        crate::network_probe::JAVA_USER_AGENT,
    ));
    state.record_event(preflight_probe_dependency("ordinary-client"));
    state.recorder().finish_run().await.unwrap();

    let global =
        tokio::fs::read_to_string(state.recorder().run_dir.join("global-dependencies.jsonl"))
            .await
            .unwrap();
    assert_eq!(global.lines().count(), 2);
    assert_eq!(
        global
            .matches("\"global_dependency_reason\":\"preflight_probe\"")
            .count(),
        1
    );
    assert!(global.contains("\"global_dependency_phase\":\"runtime\""));
    assert!(global.contains("\"global_dependency_matched_by\":\"java_truststore\""));
}

fn motan_dependency(group: &str, interface_name: &str, method_name: &str) -> RecorderEvent {
    RecorderEvent::MotanExchange(MotanExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        target_host: "vintage-node-10-145-1-1.trp.test".to_string(),
        target_port: 8882,
        target_addr: "vintage-node-10-145-1-1.trp.test:8882".to_string(),
        advertised_ip: "198.19.0.10".parse().unwrap(),
        upstream_addr: "10.145.1.1:8882".to_string(),
        codec_version: 1,
        group: Some(group.to_string()),
        interface_name: Some(interface_name.to_string()),
        method_name: Some(method_name.to_string()),
        parameter_desc: None,
        method_sign: None,
        command: format!("{interface_name}#{method_name}"),
        request: capture_body(b"request", 7),
        response_status: "value".to_string(),
        response: capture_body(b"response", 8),
        heartbeat: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

fn redis_dependency(host: &str, port: u16, key: &str) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        target_host: host.to_string(),
        target_port: port,
        target_addr: format!("{host}:{port}"),
        upstream_addr: format!("127.0.0.1:{port}"),
        resp_version: 2,
        database: 0,
        username: None,
        command: "ZCOUNT".to_string(),
        args: vec![
            capture_body(key.as_bytes(), key.len()),
            capture_body(b"1550.0", 6),
            capture_body(b"1.7976931348623157E308", 22),
        ],
        response_kind: "integer".to_string(),
        response: capture_body(b":1\r\n", 4),
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

fn redis_get_dependency(host: &str, port: u16, key: &str) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        target_host: host.to_string(),
        target_port: port,
        target_addr: format!("{host}:{port}"),
        upstream_addr: format!("127.0.0.1:{port}"),
        resp_version: 2,
        database: 0,
        username: None,
        command: "GET".to_string(),
        args: vec![capture_body(key.as_bytes(), key.len())],
        response_kind: "bulk".to_string(),
        response: capture_body(b"$5\r\nvalue\r\n", 11),
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

#[tokio::test]
async fn background_http_enters_global_pool_but_not_case_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.traffic_jsonl = TrafficJsonlMode::Full;
    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::Http {
        name: "config-refresh".to_string(),
        authorities: vec!["config.api.demo.test".to_string()],
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/1/config/service".to_string()],
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
    assert!(!global.contains("global_dependency_response_role"));
}

#[tokio::test]
async fn background_motan_enters_global_pool_but_not_case_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let interface_name = "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc";
    let method_name = "getConfigByName";
    let group = "kunpeng-config-rpc";
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::Motan {
        name: "kunpeng-refresh".to_string(),
        group: group.to_string(),
        interface_name: interface_name.to_string(),
        method_name: method_name.to_string(),
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "MapiConfigLoader.java:init scheduled refresh".to_string(),
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

    state.record_event(motan_dependency(group, interface_name, method_name));
    drop(guard);
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().finish_run().await.unwrap();

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
    assert!(global.contains(&format!("\"group\":\"{group}\"")));
    assert!(global.contains(&format!("\"interface_name\":\"{interface_name}\"")));
    assert!(global.contains("\"global_dependency_reason\":\"background_rule\""));
    assert!(global.contains("\"global_dependency_matched_by\":\"kunpeng-refresh\""));
}

#[tokio::test]
async fn background_redis_uses_ports_without_domain_and_stays_out_of_cases() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::Redis {
        name: "interest-tag-mining-cache-refresh".to_string(),
        ports: vec![20917, 20918, 20919],
        command: "ZCOUNT".to_string(),
        keys: Vec::new(),
        key_patterns: Vec::new(),
        key_prefix: "1042015:".to_string(),
        key_suffix: ".wtm2".to_string(),
        initial_load_timeout_ms: None,
        fields: Vec::new(),
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "InterestTagCardServiceImpl.java:init process-owned refresh".to_string(),
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

    state.record_event(redis_dependency(
        "new-operations-domain.example",
        20918,
        "1042015:202607:financeStock.wtm2",
    ));
    drop(guard);
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().finish_run().await.unwrap();

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
    assert!(global.contains("\"target_host\":\"new-operations-domain.example\""));
    assert!(global.contains("\"target_port\":20918"));
    assert!(global.contains("\"global_dependency_reason\":\"background_rule\""));
    assert!(!global.contains("global_dependency_response_role"));
    assert!(
        global.contains("\"global_dependency_matched_by\":\"interest-tag-mining-cache-refresh\"")
    );
}

#[tokio::test]
async fn redis_get_background_rule_records_without_response_role_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::Redis {
        name: "startup-cache-warm".to_string(),
        ports: vec![20917],
        command: "GET".to_string(),
        keys: vec!["cache:init:a".to_string()],
        key_patterns: Vec::new(),
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: Some(1_000),
        fields: Vec::new(),
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "src/cache/warm.rs:init loads response-driving local state".to_string(),
    }];
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.dns_mock.registry_path = temp.path().join("fake-dns.json");
    config.http_gateway.enabled = true;
    config.http_gateway.ready.enabled = true;
    let state = AppState::new(config).await.unwrap();

    state.record_event(redis_get_dependency("cache.service", 20917, "cache:init:a"));
    state.recorder().finish_run().await.unwrap();

    let global =
        tokio::fs::read_to_string(state.recorder().run_dir.join("global-dependencies.jsonl"))
            .await
            .unwrap();
    assert_eq!(global.lines().count(), 1);
    assert!(global.contains("\"global_dependency_reason\":\"background_rule\""));
    assert!(global.contains("\"global_dependency_matched_by\":\"startup-cache-warm\""));
    assert!(!global.contains("global_dependency_response_role"));
}

#[tokio::test]
async fn background_mysql_scan_enters_global_while_user_query_remains_case_owned() {
    use crate::recorder::{MysqlColumn, MysqlExchangeEvent, MysqlExchangeResponse};
    let temp = tempfile::tempdir().unwrap();
    let mut config = case_limit_test_config(&temp);
    config.http_gateway.ready.enabled = false;
    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::Mysql {
        name: "task-recovery".into(),
        selector: MysqlBackgroundSelector {
            target_host: "mysql.internal".into(),
            target_port: 3306,
            database: "appdb".into(),
            username: "root".into(),
            sql: "SELECT id FROM {{table}} WHERE status='RUNNING' AND created_at>=?".into(),
            tables: vec![],
            table_patterns: Vec::new(),
            table_series: Some(MysqlBackgroundTableSeries {
                prefix: "video_tasks_".into(),
                start: 0,
                end: 1023,
                width: 4,
            }),
        },
        source_revision: "0123456789abcdef".into(),
        source_evidence: "src/recovery.py:run startup scan".into(),
    }];
    let state = AppState::new(config).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "devices".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let event = |sql: &str| {
        RecorderEvent::MysqlExchange(MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            query_sequence: 1,
            timestamp: Utc::now(),
            client_addr: None,
            route_name: None,
            target_host: Some("mysql.internal".into()),
            target_port: Some(3306),
            target_addr: Some("mysql.internal:3306".into()),
            upstream_addr: None,
            database: Some("appdb".into()),
            username: Some("root".into()),
            command: "COM_QUERY".into(),
            sql: Some(sql.into()),
            statement_id: None,
            params: None,
            server_status_before: None,
            response: MysqlExchangeResponse {
                server_status: None,
                status: "resultset".into(),
                error_code: None,
                error_message: None,
                affected_rows: None,
                last_insert_id: None,
                columns: vec![MysqlColumn {
                    name: "id".into(),
                    table: None,
                    column: None,
                    family: "integer".into(),
                    sql_type: "INT".into(),
                    column_type_code: 3,
                    flags: Some(1),
                    unsigned: Some(false),
                    bits: Some(32),
                    nullable: Some(false),
                    scale: None,
                }],
                rows: vec![],
                row_count: 0,
                rows_truncated: false,
            },
            outcome: DependencyExchangeOutcome::Response,
            duration_ms: 0,
            parse_warnings: vec![],
        })
    };
    state.record_event(event(
        "SELECT id FROM video_tasks_0509 WHERE status='RUNNING' AND created_at>='2026-09-05'",
    ));
    state.record_event(event("SELECT id FROM users WHERE user_name='AbC'"));
    drop(guard);
    state.recorder().publish_case(&case).await.unwrap();
    state.recorder().finish_run().await.unwrap();
    let global =
        tokio::fs::read_to_string(state.recorder().run_dir.join("global-dependencies.jsonl"))
            .await
            .unwrap();
    let dependencies =
        tokio::fs::read_to_string(state.recorder().case_dir(&case).join("dependencies.jsonl"))
            .await
            .unwrap();
    assert_eq!(global.lines().count(), 1);
    assert!(global.contains("video_tasks_0509"));
    assert!(global.contains("\"global_dependency_reason\":\"background_rule\""));
    assert!(global.contains("\"global_dependency_matched_by\":\"task-recovery\""));
    assert_eq!(dependencies.lines().count(), 1);
    assert!(dependencies.contains("FROM users"));
}
