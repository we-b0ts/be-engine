use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::config::AppConfig;
use crate::dependency::DependencyExchangeOutcome;
use crate::recorder::{RecorderEvent, RedisExchangeEvent, capture_body};

fn rule() -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Redis {
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
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
        source_evidence: "InterestTagCardServiceImpl.java:init scheduled refresh".to_string(),
    }
}

fn get_rule() -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Redis {
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "startup-cache-warm".to_string(),
        ports: vec![20917, 20918, 20919],
        command: "GET".to_string(),
        keys: vec!["cache:init:a".to_string(), "cache:init:b".to_string()],
        key_patterns: Vec::new(),
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: Some(60_000),
        fields: Vec::new(),
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
fn validates_zcount_redis_rule() {
    let rules: super::super::SourceTrafficPolicyConfig = serde_yaml::from_str(
        r#"
        version: 1
        process_owned_dependencies:
        - name: interest-tag-mining-cache-refresh
          protocol: redis
          ports: [20917, 20918, 20919]
          command: ZCOUNT
          key_prefix: "1042015:"
          key_suffix: .wtm2
          source_revision: 0123456789abcdef
          source_evidence: InterestTagCardServiceImpl.java:init scheduled refresh
        "#,
    )
    .unwrap();
    let config = AppConfig {
        process_owned_dependencies: rules.process_owned_dependencies,
        ..Default::default()
    };
    config.validate().unwrap();

    let mut duplicate_port = config;
    let BackgroundDependencyRuleConfig::Redis { ports, .. } =
        &mut duplicate_port.process_owned_dependencies[0]
    else {
        panic!("expected Redis background rule");
    };
    ports.push(20917);
    assert!(duplicate_port.validate().is_err());
}

#[test]
fn matches_only_exact_get_keys() {
    let rule = get_rule();
    assert!(rule.matches(&event("redis.internal", 20917, "GET", "cache:init:a",)));
    assert!(!rule.matches(&event("redis.internal", 20917, "GET", "cache:init:c",)));
    assert!(!rule.matches(&event("redis.internal", 20917, "ZCOUNT", "cache:init:a",)));
}

#[test]
fn matches_scard_and_hgetall_only_on_their_exact_keys() {
    for command in ["SCARD", "HGETALL"] {
        let mut rule = get_rule();
        let BackgroundDependencyRuleConfig::Redis {
            command: configured_command,
            ..
        } = &mut rule
        else {
            panic!("expected Redis background rule");
        };
        *configured_command = command.to_string();

        validate(std::slice::from_ref(&rule)).unwrap();
        assert!(rule.matches(&event("redis.internal", 20917, command, "cache:init:a",)));
        assert!(!rule.matches(&event("redis.internal", 20917, command, "cache:init:c",)));
        assert!(!rule.matches(&event("redis.internal", 20917, "GET", "cache:init:a",)));
    }
}

#[test]
fn rejects_unlisted_exact_key_redis_commands() {
    let mut rule = get_rule();
    let BackgroundDependencyRuleConfig::Redis { command, .. } = &mut rule else {
        panic!("expected Redis background rule");
    };
    *command = "SMEMBERS".to_string();

    let error = validate(&[rule]).unwrap_err().to_string();
    assert!(error.contains("ZCOUNT"));
    assert!(error.contains("SCARD"));
    assert!(error.contains("HGETALL"));
    assert!(error.contains("HSCAN"));
}

#[test]
fn matches_bootstrap_hash_reads_by_numeric_key_shape_and_exact_fields() {
    let rule = BackgroundDependencyRuleConfig::Redis {
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "experiment-bootstrap".to_string(),
        ports: vec![6379],
        command: "HMGET".to_string(),
        keys: vec!["traffic-result".to_string()],
        key_patterns: vec![RedisKeyPatternConfig {
            prefix: "exp:matchlist:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: vec![
            "value".to_string(),
            "compress".to_string(),
            "hash".to_string(),
        ],
        source_revision: String::new(),
        source_evidence: "src/bootstrap.rs:load experiment cache".to_string(),
    };
    validate(std::slice::from_ref(&rule)).unwrap();
    assert!(redis_rule_matches(
        &rule,
        6379,
        "HMGET",
        &[
            b"exp:matchlist:123".to_vec(),
            b"value".to_vec(),
            b"compress".to_vec(),
            b"hash".to_vec(),
        ],
    ));
    assert!(!redis_rule_matches(
        &rule,
        6379,
        "HMGET",
        &[
            b"exp:matchlist:not-a-number".to_vec(),
            b"value".to_vec(),
            b"compress".to_vec(),
            b"hash".to_vec(),
        ],
    ));
    assert!(!redis_rule_matches(
        &rule,
        6379,
        "HMGET",
        &[b"traffic-result".to_vec(), b"hash".to_vec()],
    ));
}

#[test]
fn matches_process_owned_hscan_by_numeric_key_shape_without_fields() {
    let rule = BackgroundDependencyRuleConfig::Redis {
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "dingtalk-card-inbox-recovery".to_string(),
        ports: vec![6379],
        command: "HSCAN".to_string(),
        keys: Vec::new(),
        key_patterns: vec![RedisKeyPatternConfig {
            prefix: "dingtalk:card_inbox:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: Vec::new(),
        source_revision: String::new(),
        source_evidence: "CardActionInbox.list_pending scans process-owned recovery work"
            .to_string(),
    };
    validate(std::slice::from_ref(&rule)).unwrap();
    assert!(redis_rule_matches(
        &rule,
        6379,
        "HSCAN",
        &[b"dingtalk:card_inbox:257968".to_vec(), b"0".to_vec()],
    ));
    assert!(!redis_rule_matches(
        &rule,
        6379,
        "HSCAN",
        &[b"dingtalk:card_inbox:unknown".to_vec(), b"0".to_vec()],
    ));
    assert!(!redis_rule_matches(
        &rule,
        6379,
        "HGETALL",
        &[b"dingtalk:card_inbox:257968".to_vec()],
    ));
}

#[test]
fn hscan_rejects_initial_load_timeout_and_fields() {
    let mut rule = BackgroundDependencyRuleConfig::Redis {
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "dingtalk-card-inbox-recovery".to_string(),
        ports: vec![6379],
        command: "HSCAN".to_string(),
        keys: vec!["dingtalk:card_inbox:257968".to_string()],
        key_patterns: Vec::new(),
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: Some(60_000),
        fields: Vec::new(),
        source_revision: String::new(),
        source_evidence: "CardActionInbox.list_pending scans process-owned recovery work"
            .to_string(),
    };
    let error = validate(std::slice::from_ref(&rule))
        .unwrap_err()
        .to_string();
    assert!(error.contains("must not use initial_load_timeout_ms"));

    let BackgroundDependencyRuleConfig::Redis {
        initial_load_timeout_ms,
        fields,
        ..
    } = &mut rule
    else {
        panic!("expected Redis background rule");
    };
    *initial_load_timeout_ms = None;
    fields.push("unrelated".to_string());
    let error = validate(&[rule]).unwrap_err().to_string();
    assert!(error.contains("must not use fields"));
}

#[test]
fn redis_get_requires_exact_keys_timeout_and_ready_probe() {
    let mut config = AppConfig {
        process_owned_dependencies: vec![get_rule()],
        ..Default::default()
    };
    let error = config.validate().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("initial-load observation requires an enabled HTTP gateway ready probe")
    );

    config.http_gateway.enabled = true;
    config.http_gateway.ready.enabled = true;
    config.validate().unwrap();

    let BackgroundDependencyRuleConfig::Redis {
        initial_load_timeout_ms,
        ..
    } = &mut config.process_owned_dependencies[0]
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
