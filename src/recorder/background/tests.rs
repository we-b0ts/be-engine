use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::DependencyExchangeOutcome;
use crate::recorder::{MemcachedExchangeEvent, RedisExchangeEvent};

fn memcached_rule_with(
    identity: String,
    key_end: u64,
    initial_load_timeout_ms: u64,
) -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Memcached {
        name: "planet-video-cache-warm".to_string(),
        breeze_identity: identity,
        command: "get".to_string(),
        key_start: 0,
        key_end,
        key_separator: ".".to_string(),
        key_suffix: "pl_video".to_string(),
        initial_load_timeout_ms,
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "TopUserServiceImpl.java:691 scheduled local cache warm".to_string(),
    }
}

fn memcached_rule(identity: String) -> BackgroundDependencyRuleConfig {
    memcached_rule_with(identity, 4095, 60_000)
}

fn event(port: u16, command: &str, key: &[u8]) -> RecorderEvent {
    RecorderEvent::MemcachedExchange(MemcachedExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        target_host: "breeze.recording".to_string(),
        target_port: port,
        target_addr: format!("breeze.recording:{port}"),
        upstream_addr: format!("127.0.0.1:{port}"),
        wire_protocol: "binary".to_string(),
        command: command.to_string(),
        opcode: Some(0),
        opaque: Some(1),
        key: Some(crate::recorder::capture_body(key, key.len())),
        args: Vec::new(),
        value: None,
        extras: None,
        cas: None,
        noreply: false,
        quiet: false,
        response_status: "0".to_string(),
        response_frames: Vec::new(),
        no_response: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

fn redis_get_rule() -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Redis {
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "startup-cache-warm".to_string(),
        ports: vec![20917, 20918],
        command: "GET".to_string(),
        keys: vec!["cache:init:a".to_string(), "cache:init:b".to_string()],
        key_patterns: Vec::new(),
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: Some(50),
        fields: Vec::new(),
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "src/cache/warm.rs:init loads response-driving local state".to_string(),
    }
}

fn redis_event(port: u16, command: &str, key: &[u8]) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        target_host: "redis.internal".to_string(),
        target_port: port,
        target_addr: format!("redis.internal:{port}"),
        upstream_addr: format!("127.0.0.1:{port}"),
        resp_version: 2,
        database: 0,
        username: None,
        command: command.to_string(),
        args: vec![crate::recorder::capture_body(key, key.len())],
        response_kind: "bulk_string".to_string(),
        response: crate::recorder::capture_body(b"$1\r\n1\r\n", 7),
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

#[test]
fn matches_exact_get_key_series_on_an_existing_descriptor() {
    let temp = tempfile::tempdir().unwrap();
    let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
    std::fs::write(temp.path().join(filename), "").unwrap();
    let identity = filename.replace(":9448", "");
    let matcher =
        BackgroundDependencyMatcher::from_rules_in(&[memcached_rule(identity)], temp.path())
            .unwrap();

    assert_eq!(
        matcher
            .matching_rule(&event(9448, "get", b"0.pl_video"))
            .map(|matched| matched.rule_name().to_string()),
        Some("planet-video-cache-warm".to_string())
    );
    assert_eq!(
        matcher
            .matching_rule(&event(9448, "GET", b"4095.pl_video"))
            .map(|matched| matched.rule_name().to_string()),
        Some("planet-video-cache-warm".to_string())
    );
    assert!(
        matcher
            .matching_rule(&event(9449, "get", b"0.pl_video"))
            .is_none()
    );
    assert!(
        matcher
            .matching_rule(&event(9448, "set", b"0.pl_video"))
            .is_none()
    );
    assert!(
        matcher
            .matching_rule(&event(9448, "get", b"4096.pl_video"))
            .is_none()
    );
    assert!(
        matcher
            .matching_rule(&event(9448, "get", b"00.pl_video"))
            .is_none()
    );
    assert!(
        matcher
            .matching_rule(&event(9448, "get", b"0.other"))
            .is_none()
    );
}

#[test]
fn resolves_source_registered_descriptor_after_recorder_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
    let identity = filename.replace(":9448", "");
    let matcher =
        BackgroundDependencyMatcher::from_rules_in(&[memcached_rule(identity)], temp.path())
            .unwrap();

    assert!(matcher.ensure_resources_resolved().is_err());
    assert!(
        matcher
            .matching_rule(&event(9449, "get", b"0.pl_video"))
            .is_none()
    );

    std::fs::write(temp.path().join(filename), "").unwrap();

    assert_eq!(
        matcher
            .matching_rule(&event(9448, "get", b"0.pl_video"))
            .map(|matched| matched.rule_name().to_string()),
        Some("planet-video-cache-warm".to_string())
    );
    assert!(matcher.pending_resource_summary().is_empty());
    matcher.ensure_resources_resolved().unwrap();
}

#[tokio::test]
async fn initial_load_completion_uses_matching_exchange_count() {
    let temp = tempfile::tempdir().unwrap();
    let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
    std::fs::write(temp.path().join(filename), "").unwrap();
    let identity = filename.replace(":9448", "");
    let matcher = BackgroundDependencyMatcher::from_rules_in(
        &[memcached_rule_with(identity, 2, 50)],
        temp.path(),
    )
    .unwrap();

    for _ in 0..3 {
        let matched = matcher
            .matching_rule(&event(9448, "get", b"0.pl_video"))
            .unwrap();
        matcher.record_completed_match(&matched);
    }

    matcher.wait_for_initial_loads().await;
}

#[tokio::test]
async fn initial_load_timeout_is_non_fatal() {
    let temp = tempfile::tempdir().unwrap();
    let filename = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";
    std::fs::write(temp.path().join(filename), "").unwrap();
    let identity = filename.replace(":9448", "");
    let matcher = BackgroundDependencyMatcher::from_rules_in(
        &[memcached_rule_with(identity, 1, 5)],
        temp.path(),
    )
    .unwrap();
    let matched = matcher
        .matching_rule(&event(9448, "get", b"0.pl_video"))
        .unwrap();
    matcher.record_completed_match(&matched);

    matcher.wait_for_initial_loads().await;
    assert_eq!(matcher.pending_initial_loads().len(), 1);
}

#[tokio::test]
async fn redis_exact_key_initial_load_requires_each_key_for_the_configured_command() {
    for command in ["GET", "SCARD", "HGETALL"] {
        let mut rule = redis_get_rule();
        if let BackgroundDependencyRuleConfig::Redis {
            command: configured,
            ..
        } = &mut rule
        {
            *configured = command.to_string();
        }
        let matcher = BackgroundDependencyMatcher::from_rules(&[rule]).unwrap();

        for _ in 0..2 {
            let matched = matcher
                .matching_rule(&redis_event(20917, command, b"cache:init:a"))
                .unwrap();
            matcher.record_completed_match(&matched);
        }
        assert_eq!(matcher.pending_initial_loads().len(), 1);

        let matched = matcher
            .matching_rule(&redis_event(20918, command, b"cache:init:b"))
            .unwrap();
        matcher.record_completed_match(&matched);
        matcher.wait_for_initial_loads().await;
        assert!(matcher.pending_initial_loads().is_empty());
    }
}
