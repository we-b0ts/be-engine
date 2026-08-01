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
        key_prefix: "1042015:".to_string(),
        key_suffix: ".wtm2".to_string(),
        response_role: BackgroundDependencyResponseRole::Independent,
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "InterestTagCardServiceImpl.java:init scheduled refresh".to_string(),
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
