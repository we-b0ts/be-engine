use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::config::AppConfig;
use crate::dependency::DependencyExchangeOutcome;
use crate::recorder::{BodyCapture, HttpExchangeEvent, MotanExchangeEvent};

fn http_event(authority: &str, method: &str, uri: &str) -> RecorderEvent {
    RecorderEvent::HttpExchange(HttpExchangeEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        client_addr: None,
        scheme: "https".to_string(),
        method: method.to_string(),
        uri: uri.to_string(),
        authority: Some(authority.to_string()),
        request_headers: Default::default(),
        request_body: BodyCapture {
            encoding: "utf8",
            original_len: 0,
            stored_len: 0,
            truncated: false,
            data: String::new(),
        },
        response_status: Some(200),
        response_headers: Some(Default::default()),
        response_body: None,
        discovered_tcp_targets: Vec::new(),
        duration_ms: 10,
        error: None,
    })
}

fn memcached_rule(timeout_ms: u64) -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Memcached {
        name: "planet-video-cache-warm".to_string(),
        breeze_identity: "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc@cs"
            .to_string(),
        command: "get".to_string(),
        key_start: 0,
        key_end: 4095,
        key_separator: ".".to_string(),
        key_suffix: "pl_video".to_string(),
        initial_load_timeout_ms: timeout_ms,
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "TopUserServiceImpl.java:691 scheduled local cache warm".to_string(),
    }
}

fn motan_event(
    group: &str,
    interface_name: &str,
    method_name: &str,
    heartbeat: bool,
) -> RecorderEvent {
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
        request: crate::recorder::capture_body(&[], 0),
        response_status: "value".to_string(),
        response: crate::recorder::capture_body(&[], 0),
        heartbeat,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

#[test]
fn http_rule_matches_authority_method_and_path_without_weakening_query_identity() {
    let rule = BackgroundDependencyRuleConfig::Http {
        name: "config-refresh".to_string(),
        authorities: vec!["CONFIG.API.demo.test".to_string()],
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/1/config/service".to_string()],
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
    };

    assert!(rule.matches(&http_event(
        "config.api.demo.test",
        "GET",
        "/1/config/service?action=lookup&group=large"
    )));
    assert!(!rule.matches(&http_event(
        "config.api.demo.test",
        "POST",
        "/1/config/service?action=lookup"
    )));
    assert!(!rule.matches(&http_event(
        "other.api.demo.test",
        "GET",
        "/1/config/service?action=lookup"
    )));
}

#[test]
fn parses_and_validates_http_background_rules() {
    let rules: super::super::CoordinatorRulesConfig = serde_yaml::from_str(
        r#"
        version: 1
        process_owned_dependencies:
        - name: config-refresh
          protocol: http
          authorities: [config.api.demo.test]
          methods: [GET]
          path_prefixes: [/1/config/service]
          source_revision: 0123456789abcdef
          source_evidence: src/config/refresh.rs:42 scheduled refresh
        "#,
    )
    .unwrap();
    let config = AppConfig {
        process_owned_dependencies: rules.process_owned_dependencies,
        ..Default::default()
    };
    config.validate().unwrap();

    let mut duplicate = config.clone();
    duplicate
        .process_owned_dependencies
        .push(duplicate.process_owned_dependencies[0].clone());
    assert!(duplicate.validate().is_err());
}

#[test]
fn inline_process_owned_dependencies_are_rejected() {
    let error = toml::from_str::<AppConfig>(
        r#"
        [recording]

        [[recording.process_owned_dependencies]]
        name = "legacy-config-refresh"
        protocol = "http"
        authorities = ["config.api.demo.test"]
        methods = ["GET"]
        path_prefixes = ["/1/config/service"]
        source_revision = "0123456789abcdef"
        source_evidence = "src/config/refresh.rs:42 scheduled refresh"
        "#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn motan_rule_matches_exact_business_method_but_never_heartbeat() {
    let interface_name = "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc";
    let method_name = "getConfigByName";
    let rule = BackgroundDependencyRuleConfig::Motan {
        name: "kunpeng-refresh".to_string(),
        group: "kunpeng-config-rpc".to_string(),
        interface_name: interface_name.to_string(),
        method_name: method_name.to_string(),
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "MapiConfigLoader.java:init scheduled refresh".to_string(),
    };

    assert!(rule.matches(&motan_event(
        "kunpeng-config-rpc",
        interface_name,
        method_name,
        false
    )));
    assert!(!rule.matches(&motan_event(
        "kunpeng-config-rpc-sandbox",
        interface_name,
        method_name,
        false
    )));
    assert!(!rule.matches(&motan_event(
        "kunpeng-config-rpc",
        interface_name,
        "getOtherConfig",
        false
    )));
    let heartbeat_rule = BackgroundDependencyRuleConfig::Motan {
        name: "invalid-heartbeat-background".to_string(),
        group: "motan-heartbeat".to_string(),
        interface_name: "com.weibo.api.motan.rpc.heartbeat".to_string(),
        method_name: "heartbeat".to_string(),
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "heartbeat must remain protocol-owned".to_string(),
    };
    assert!(!heartbeat_rule.matches(&motan_event(
        "motan-heartbeat",
        "com.weibo.api.motan.rpc.heartbeat",
        "heartbeat",
        true,
    )));
}

#[test]
fn parses_and_validates_exact_motan_background_rules() {
    let rules: super::super::CoordinatorRulesConfig = serde_yaml::from_str(
        r#"
        version: 1
        process_owned_dependencies:
        - name: kunpeng-refresh
          protocol: motan
          group: kunpeng-config-rpc
          interface_name: com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc
          method_name: getConfigByName
          source_revision: 0123456789abcdef
          source_evidence: MapiConfigLoader.java:init scheduled refresh
        "#,
    )
    .unwrap();
    let config = AppConfig {
        process_owned_dependencies: rules.process_owned_dependencies,
        ..Default::default()
    };
    config.validate().unwrap();

    let mut overlapping = config.clone();
    let mut duplicate = overlapping.process_owned_dependencies[0].clone();
    let BackgroundDependencyRuleConfig::Motan { name, .. } = &mut duplicate else {
        panic!("expected Motan background rule");
    };
    *name = "duplicate-kunpeng-refresh".to_string();
    overlapping.process_owned_dependencies.push(duplicate);
    assert!(overlapping.validate().is_err());

    let mut distinct_group = config.clone();
    let mut sandbox = distinct_group.process_owned_dependencies[0].clone();
    let BackgroundDependencyRuleConfig::Motan { name, group, .. } = &mut sandbox else {
        panic!("expected Motan background rule");
    };
    *name = "sandbox-kunpeng-refresh".to_string();
    *group = "kunpeng-config-rpc-sandbox".to_string();
    distinct_group.process_owned_dependencies.push(sandbox);
    distinct_group.validate().unwrap();

    let mut invalid = config;
    let BackgroundDependencyRuleConfig::Motan { method_name, .. } =
        &mut invalid.process_owned_dependencies[0]
    else {
        panic!("expected Motan background rule");
    };
    *method_name = "get*".to_string();
    assert!(invalid.validate().is_err());
}

#[test]
fn accepts_bounded_http_selector_sets_and_rejects_invalid_rules() {
    let mut config = AppConfig {
        process_owned_dependencies: vec![BackgroundDependencyRuleConfig::Http {
            name: "too-broad".to_string(),
            authorities: vec!["config.api.demo.test".to_string()],
            methods: Vec::new(),
            path_prefixes: vec!["/".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }],
        ..Default::default()
    };
    assert!(config.validate().is_err());

    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::Http {
        name: "invalid-path".to_string(),
        authorities: vec!["config.api.demo.test".to_string()],
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/lookup?group=x".to_string()],
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
    }];
    assert!(config.validate().is_err());

    let rule = BackgroundDependencyRuleConfig::Http {
        name: "breeze_vintage".to_string(),
        authorities: vec![
            "config.api.demo.test".to_string(),
            "static.config.api.demo.test".to_string(),
        ],
        methods: vec!["GET".to_string()],
        path_prefixes: vec![
            "/1/config/service".to_string(),
            "/naming/service".to_string(),
        ],
        source_revision: "0123456789abcdef".to_string(),
        source_evidence: "traffic-e2e system default: Breeze Vintage background".to_string(),
    };
    config.process_owned_dependencies = vec![rule.clone()];
    config.validate().unwrap();
    assert!(rule.matches(&http_event(
        "config.api.demo.test",
        "GET",
        "/naming/service?action=lookup"
    )));
    assert!(rule.matches(&http_event(
        "static.config.api.demo.test",
        "GET",
        "/1/config/service?action=getsign"
    )));

    let mut overlapping = rule;
    let BackgroundDependencyRuleConfig::Http {
        name,
        authorities,
        path_prefixes,
        ..
    } = &mut overlapping
    else {
        panic!("expected HTTP background rule");
    };
    *name = "overlapping-vintage".to_string();
    *authorities = vec!["config.api.demo.test".to_string()];
    *path_prefixes = vec!["/naming/service".to_string()];
    config.process_owned_dependencies.push(overlapping);
    assert!(config.validate().is_err());

    let too_many = AppConfig {
        process_owned_dependencies: vec![BackgroundDependencyRuleConfig::Http {
            name: "too-many-authorities".to_string(),
            authorities: (0..=MAX_HTTP_AUTHORITIES)
                .map(|index| format!("config-{index}.example.test"))
                .collect(),
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/1/config/service".to_string()],
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "bounded selector test".to_string(),
        }],
        ..Default::default()
    };
    assert!(too_many.validate().is_err());
}

#[test]
fn memcached_initial_load_requires_ready_probe_and_positive_timeout() {
    let mut config = AppConfig {
        process_owned_dependencies: vec![memcached_rule(30_000)],
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

    config.process_owned_dependencies = vec![memcached_rule(0)];
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("initial_load_timeout_ms"));
}

#[test]
fn memcached_initial_load_accepts_u64_profile_keys() {
    assert!(matches_memcached_key_series(
        b"5000000000.profile",
        5_000_000_000,
        5_000_000_000,
        b'.',
        b"profile",
    ));
    assert!(!matches_memcached_key_series(
        b"5000000001.profile",
        5_000_000_000,
        5_000_000_000,
        b'.',
        b"profile",
    ));
}
