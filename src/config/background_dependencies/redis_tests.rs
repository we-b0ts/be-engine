use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::config::AppConfig;
use crate::dependency::DependencyExchangeOutcome;
use crate::recorder::{RecorderEvent, RedisExchangeEvent, capture_body};

fn rule() -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Redis {
        name: "interest-tag-mining-cache-refresh".to_string(),
        ports: vec![20917, 20918, 20919],
        command: "ZCOUNT".to_string(),
        keys: Vec::new(),
        key_prefix: "1042015:".to_string(),
        key_suffix: ".wtm2".to_string(),
        initial_load_timeout_ms: None,
        response_role: BackgroundDependencyResponseRole::Independent,
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "InterestTagCardServiceImpl.java:init scheduled refresh".to_string(),
    }
}

fn runtime_state_rule() -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Redis {
        name: "startup-cache-warm".to_string(),
        ports: vec![20917, 20918, 20919],
        command: "GET".to_string(),
        keys: vec!["cache:init:a".to_string(), "cache:init:b".to_string()],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: Some(60_000),
        response_role: BackgroundDependencyResponseRole::RuntimeState,
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "src/cache/warm.rs:init loads response-driving local state".to_string(),
    }
}

fn event(host: &str, port: u16, command: &str, key: &str) -> RecorderEvent {
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
        command: command.to_string(),
        args: vec![capture_body(key.as_bytes(), key.len())],
        response_kind: "integer".to_string(),
        response: capture_body(b":1\r\n", 4),
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

#[test]
fn matches_ports_command_and_key_shape_without_domain_identity() {
    let rule = rule();
    assert!(rule.matches(&event(
        "rs20917.hebe.grid.sample.test",
        20917,
        "ZCOUNT",
        "1042015:202607:financeStock.wtm2",
    )));
    assert!(rule.matches(&event(
        "new-operations-domain.example",
        20918,
        "zcount",
        "1042015:202608:other.wtm2",
    )));
    assert!(!rule.matches(&event(
        "rs20920.hebe.grid.sample.test",
        20920,
        "ZCOUNT",
        "1042015:202607:financeStock.wtm2",
    )));
    assert!(!rule.matches(&event(
        "rs20917.hebe.grid.sample.test",
        20917,
        "GET",
        "1042015:202607:financeStock.wtm2",
    )));
    assert!(!rule.matches(&event(
        "rs20917.hebe.grid.sample.test",
        20917,
        "ZCOUNT",
        "1042015:202607:financeStock.other",
    )));
}

#[test]
fn validates_global_independent_redis_rule() {
    let config: AppConfig = toml::from_str(
        r#"
        [recording]

        [[recording.background_dependencies]]
        name = "interest-tag-mining-cache-refresh"
        protocol = "redis"
        ports = [20917, 20918, 20919]
        command = "ZCOUNT"
        key_prefix = "1042015:"
        key_suffix = ".wtm2"
        response_role = "independent"
        source_revision = "0123456789abcdef"
        source_evidence = "InterestTagCardServiceImpl.java:init scheduled refresh"
        "#,
    )
    .unwrap();
    config.validate().unwrap();

    let mut duplicate_port = config;
    let BackgroundDependencyRuleConfig::Redis { ports, .. } =
        &mut duplicate_port.recording.background_dependencies[0]
    else {
        panic!("expected Redis background rule");
    };
    ports.push(20917);
    assert!(duplicate_port.validate().is_err());
}

#[test]
fn matches_only_exact_runtime_state_get_keys() {
    let rule = runtime_state_rule();
    assert!(rule.matches(&event("redis.internal", 20917, "GET", "cache:init:a",)));
    assert!(!rule.matches(&event("redis.internal", 20917, "GET", "cache:init:c",)));
    assert!(!rule.matches(&event("redis.internal", 20917, "ZCOUNT", "cache:init:a",)));
}

#[test]
fn runtime_state_redis_requires_exact_keys_timeout_and_ready_probe() {
    let mut config = AppConfig::default();
    config.recording.background_dependencies = vec![runtime_state_rule()];
    let error = config.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("require an enabled HTTP gateway ready probe")
    );

    config.http_gateway.enabled = true;
    config.http_gateway.ready.enabled = true;
    config.validate().unwrap();

    let BackgroundDependencyRuleConfig::Redis {
        initial_load_timeout_ms,
        ..
    } = &mut config.recording.background_dependencies[0]
    else {
        panic!("expected Redis background rule");
    };
    *initial_load_timeout_ms = Some(0);
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("initial_load_timeout_ms")
    );
}
