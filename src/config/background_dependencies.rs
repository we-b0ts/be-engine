use std::collections::HashSet;

use anyhow::{Result, bail};
use hyper::http::{Method, Uri, uri::Authority};
use serde::{Deserialize, Serialize};

use crate::recorder::RecorderEvent;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundDependencyResponseRole {
    #[default]
    Independent,
    RuntimeState,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackgroundDependencyRuleConfig {
    Http {
        name: String,
        authorities: Vec<String>,
        methods: Vec<String>,
        path_prefixes: Vec<String>,
        #[serde(default)]
        response_role: BackgroundDependencyResponseRole,
        source_revision: String,
        source_evidence: String,
    },
    Memcached {
        name: String,
        breeze_identity: String,
        command: String,
        key_start: u32,
        key_end: u32,
        key_separator: String,
        key_suffix: String,
        initial_load_timeout_ms: u64,
        response_role: BackgroundDependencyResponseRole,
        source_revision: String,
        source_evidence: String,
    },
    Motan {
        name: String,
        group: String,
        interface_name: String,
        method_name: String,
        source_revision: String,
        source_evidence: String,
    },
}

impl BackgroundDependencyRuleConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Http { name, .. } | Self::Memcached { name, .. } | Self::Motan { name, .. } => {
                name
            }
        }
    }

    pub(crate) fn matches(&self, event: &RecorderEvent) -> bool {
        match (self, event) {
            (
                Self::Http {
                    authorities,
                    methods,
                    path_prefixes,
                    ..
                },
                RecorderEvent::HttpExchange(exchange),
            ) => {
                let Some(authority) = exchange
                    .authority
                    .as_deref()
                    .and_then(normalize_authority)
                    .or_else(|| {
                        exchange
                            .uri
                            .parse::<Uri>()
                            .ok()
                            .and_then(|uri| uri.authority().map(ToString::to_string))
                            .as_deref()
                            .and_then(normalize_authority)
                    })
                else {
                    return false;
                };
                let path = exchange
                    .uri
                    .parse::<Uri>()
                    .ok()
                    .map(|uri| uri.path().to_string())
                    .unwrap_or_else(|| {
                        exchange
                            .uri
                            .split('?')
                            .next()
                            .unwrap_or(&exchange.uri)
                            .to_string()
                    });

                authorities
                    .iter()
                    .any(|candidate| normalize_authority(candidate).as_deref() == Some(&authority))
                    && methods
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(&exchange.method))
                    && path_prefixes.iter().any(|prefix| path.starts_with(prefix))
            }
            (
                Self::Motan {
                    group,
                    interface_name,
                    method_name,
                    ..
                },
                RecorderEvent::MotanExchange(exchange),
            ) => {
                !exchange.heartbeat
                    && exchange.group.as_deref() == Some(group)
                    && exchange.interface_name.as_deref() == Some(interface_name)
                    && exchange.method_name.as_deref() == Some(method_name)
            }
            _ => false,
        }
    }
}

pub(super) fn validate(rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for rule in rules {
        let name = rule.name();
        if name.trim().is_empty() {
            bail!("background dependency rule name must not be empty");
        }
        if !names.insert(name) {
            bail!("duplicate background dependency rule name {name:?}");
        }
        match rule {
            BackgroundDependencyRuleConfig::Http {
                authorities,
                methods,
                path_prefixes,
                response_role,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_authorities(name, authorities)?;
                validate_methods(name, methods)?;
                validate_path_prefixes(name, path_prefixes)?;
                if *response_role != BackgroundDependencyResponseRole::Independent {
                    bail!("HTTP background dependency rule {name:?} must be response-independent");
                }
                validate_source_metadata(source_revision, source_evidence)?;
            }
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity,
                command,
                key_start,
                key_end,
                key_separator,
                key_suffix,
                initial_load_timeout_ms,
                response_role,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_breeze_identity(name, breeze_identity)?;
                if command != "get" {
                    bail!(
                        "Memcached background dependency rule {name:?} currently supports only command \"get\""
                    );
                }
                validate_key_series(name, *key_start, *key_end, key_separator, key_suffix)?;
                if *initial_load_timeout_ms == 0 {
                    bail!(
                        "Memcached background dependency rule {name:?} initial_load_timeout_ms must be greater than zero"
                    );
                }
                if *response_role != BackgroundDependencyResponseRole::RuntimeState {
                    bail!(
                        "Memcached background dependency rule {name:?} must use response_role = \"runtime_state\""
                    );
                }
                validate_source_metadata(source_revision, source_evidence)?;
            }
            BackgroundDependencyRuleConfig::Motan {
                group,
                interface_name,
                method_name,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_motan_identity(name, "group", group, 256)?;
                validate_motan_identity(name, "interface_name", interface_name, 512)?;
                validate_motan_identity(name, "method_name", method_name, 256)?;
                if interface_name == "com.weibo.api.motan.rpc.heartbeat"
                    && method_name == "heartbeat"
                {
                    bail!(
                        "Motan heartbeat is protocol-owned and cannot be configured as a background dependency rule"
                    );
                }
                validate_source_metadata(source_revision, source_evidence)?;
            }
        }
    }
    validate_non_overlapping_rules(rules)?;
    Ok(())
}

fn validate_source_metadata(source_revision: &str, source_evidence: &str) -> Result<()> {
    validate_single_line("background dependency source revision", source_revision, 64)?;
    if source_revision.len() < 7
        || !source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!(
            "background dependency source revision must be a 7-64 character lowercase hexadecimal revision"
        );
    }
    validate_single_line(
        "background dependency source evidence",
        source_evidence,
        1_024,
    )
}

fn validate_non_overlapping_rules(rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            if rules_overlap(left, right) {
                bail!(
                    "background dependency rules {:?} and {:?} have overlapping selectors",
                    left.name(),
                    right.name()
                );
            }
        }
    }
    Ok(())
}

fn rules_overlap(
    left: &BackgroundDependencyRuleConfig,
    right: &BackgroundDependencyRuleConfig,
) -> bool {
    match (left, right) {
        (
            BackgroundDependencyRuleConfig::Http {
                authorities: left_authorities,
                methods: left_methods,
                path_prefixes: left_paths,
                ..
            },
            BackgroundDependencyRuleConfig::Http {
                authorities: right_authorities,
                methods: right_methods,
                path_prefixes: right_paths,
                ..
            },
        ) => {
            left_authorities.iter().any(|left| {
                right_authorities
                    .iter()
                    .any(|right| normalize_authority(left) == normalize_authority(right))
            }) && left_methods.iter().any(|left| {
                right_methods
                    .iter()
                    .any(|right| left.eq_ignore_ascii_case(right))
            }) && left_paths.iter().any(|left| {
                right_paths
                    .iter()
                    .any(|right| left.starts_with(right) || right.starts_with(left))
            })
        }
        (
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity: left_identity,
                command: left_command,
                key_start: left_start,
                key_end: left_end,
                key_separator: left_separator,
                key_suffix: left_suffix,
                ..
            },
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity: right_identity,
                command: right_command,
                key_start: right_start,
                key_end: right_end,
                key_separator: right_separator,
                key_suffix: right_suffix,
                ..
            },
        ) => {
            left_identity == right_identity
                && left_command == right_command
                && left_separator == right_separator
                && left_suffix == right_suffix
                && left_start <= right_end
                && right_start <= left_end
        }
        (
            BackgroundDependencyRuleConfig::Motan {
                group: left_group,
                interface_name: left_interface,
                method_name: left_method,
                ..
            },
            BackgroundDependencyRuleConfig::Motan {
                group: right_group,
                interface_name: right_interface,
                method_name: right_method,
                ..
            },
        ) => {
            left_group == right_group
                && left_interface == right_interface
                && left_method == right_method
        }
        _ => false,
    }
}

fn validate_motan_identity(
    rule_name: &str,
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<()> {
    validate_single_line(
        &format!("Motan background dependency {field}"),
        value,
        max_len,
    )?;
    if value.contains(['*', '#']) {
        bail!(
            "Motan background dependency rule {rule_name:?} {field} must be exact and cannot contain wildcards or '#'"
        );
    }
    Ok(())
}

fn validate_breeze_identity(rule_name: &str, identity: &str) -> Result<()> {
    validate_single_line(
        "Memcached background dependency Breeze identity",
        identity,
        1_024,
    )?;
    let fields = identity.split('@').collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
        bail!(
            "Memcached background dependency rule {rule_name:?} must use a stable service@socket-type@protocol Breeze identity"
        );
    }
    if fields[1] != "mc" {
        bail!(
            "Memcached background dependency rule {rule_name:?} requires a Breeze mc socket identity"
        );
    }
    if fields[1].contains(':') {
        bail!("Memcached background dependency rule {rule_name:?} must not persist a Breeze port");
    }
    Ok(())
}

fn validate_key_series(
    rule_name: &str,
    start: u32,
    end: u32,
    separator: &str,
    suffix: &str,
) -> Result<()> {
    const MAX_KEYS: u64 = 65_536;
    if start > end {
        bail!(
            "Memcached background dependency rule {rule_name:?} key_start must not exceed key_end"
        );
    }
    if u64::from(end) - u64::from(start) + 1 > MAX_KEYS {
        bail!(
            "Memcached background dependency rule {rule_name:?} exceeds the {MAX_KEYS} key safety limit"
        );
    }
    if separator.len() != 1
        || !separator.is_ascii()
        || separator.as_bytes()[0].is_ascii_alphanumeric()
    {
        bail!(
            "Memcached background dependency rule {rule_name:?} key_separator must be one non-alphanumeric ASCII byte"
        );
    }
    validate_single_line("Memcached background dependency key suffix", suffix, 128)?;
    Ok(())
}

pub(crate) fn matches_memcached_key_series(
    key: &[u8],
    start: u32,
    end: u32,
    separator: u8,
    suffix: &[u8],
) -> bool {
    let Some(separator_index) = key.iter().position(|byte| *byte == separator) else {
        return false;
    };
    let (prefix, actual_suffix) = key.split_at(separator_index);
    if prefix.is_empty()
        || prefix.len() > 10
        || prefix.iter().any(|byte| !byte.is_ascii_digit())
        || actual_suffix.get(1..) != Some(suffix)
    {
        return false;
    }
    let Ok(prefix) = std::str::from_utf8(prefix) else {
        return false;
    };
    let Ok(value) = prefix.parse::<u32>() else {
        return false;
    };
    value >= start && value <= end && value.to_string() == prefix
}

fn validate_authorities(rule_name: &str, authorities: &[String]) -> Result<()> {
    if authorities.len() != 1 {
        bail!("HTTP background dependency rule {rule_name:?} must include exactly one authority");
    }
    let mut unique = HashSet::new();
    for authority in authorities {
        let normalized = normalize_authority(authority).ok_or_else(|| {
            anyhow::anyhow!(
                "HTTP background dependency rule {rule_name:?} has invalid authority {authority:?}"
            )
        })?;
        if !unique.insert(normalized) {
            bail!(
                "HTTP background dependency rule {rule_name:?} has duplicate authority {authority:?}"
            );
        }
    }
    Ok(())
}

fn validate_methods(rule_name: &str, methods: &[String]) -> Result<()> {
    if methods.len() != 1 {
        bail!("HTTP background dependency rule {rule_name:?} must include exactly one method");
    }
    let mut unique = HashSet::new();
    for method in methods {
        let parsed = method.parse::<Method>().map_err(|_| {
            anyhow::anyhow!(
                "HTTP background dependency rule {rule_name:?} has invalid method {method:?}"
            )
        })?;
        let normalized = parsed.as_str().to_ascii_uppercase();
        if !unique.insert(normalized) {
            bail!("HTTP background dependency rule {rule_name:?} has duplicate method {method:?}");
        }
    }
    Ok(())
}

fn validate_path_prefixes(rule_name: &str, path_prefixes: &[String]) -> Result<()> {
    if path_prefixes.len() != 1 {
        bail!("HTTP background dependency rule {rule_name:?} must include exactly one path prefix");
    }
    let mut unique = HashSet::new();
    for prefix in path_prefixes {
        if !prefix.starts_with('/') || prefix.contains('?') || prefix.contains('#') {
            bail!(
                "HTTP background dependency rule {rule_name:?} has invalid path prefix {prefix:?}"
            );
        }
        if !unique.insert(prefix) {
            bail!(
                "HTTP background dependency rule {rule_name:?} has duplicate path prefix {prefix:?}"
            );
        }
    }
    Ok(())
}

fn normalize_authority(value: &str) -> Option<String> {
    let authority = value.parse::<Authority>().ok()?;
    let host = authority.host().to_ascii_lowercase();
    Some(match authority.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn validate_single_line(label: &str, value: &str, max_len: usize) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must not be empty");
    }
    if value != value.trim() || value.contains(['\r', '\n']) {
        bail!("{label} must be a single line without surrounding whitespace");
    }
    if value.len() > max_len {
        bail!("{label} must not exceed {max_len} bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
            response_role: BackgroundDependencyResponseRole::RuntimeState,
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
            response_role: BackgroundDependencyResponseRole::Independent,
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
        let config: AppConfig = toml::from_str(
            r#"
            [recording]

            [[recording.background_dependencies]]
            name = "config-refresh"
            protocol = "http"
            authorities = ["config.api.demo.test"]
            methods = ["GET"]
            path_prefixes = ["/1/config/service"]
            source_revision = "0123456789abcdef"
            source_evidence = "src/config/refresh.rs:42 scheduled refresh"
            "#,
        )
        .unwrap();
        config.validate().unwrap();

        let mut duplicate = config.clone();
        duplicate
            .recording
            .background_dependencies
            .push(duplicate.recording.background_dependencies[0].clone());
        assert!(duplicate.validate().is_err());
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
        let config: AppConfig = toml::from_str(
            r#"
            [recording]

            [[recording.background_dependencies]]
            name = "kunpeng-refresh"
            protocol = "motan"
            group = "kunpeng-config-rpc"
            interface_name = "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc"
            method_name = "getConfigByName"
            source_revision = "0123456789abcdef"
            source_evidence = "MapiConfigLoader.java:init scheduled refresh"
            "#,
        )
        .unwrap();
        config.validate().unwrap();

        let mut overlapping = config.clone();
        let mut duplicate = overlapping.recording.background_dependencies[0].clone();
        let BackgroundDependencyRuleConfig::Motan { name, .. } = &mut duplicate else {
            panic!("expected Motan background rule");
        };
        *name = "duplicate-kunpeng-refresh".to_string();
        overlapping
            .recording
            .background_dependencies
            .push(duplicate);
        assert!(overlapping.validate().is_err());

        let mut distinct_group = config.clone();
        let mut sandbox = distinct_group.recording.background_dependencies[0].clone();
        let BackgroundDependencyRuleConfig::Motan { name, group, .. } = &mut sandbox else {
            panic!("expected Motan background rule");
        };
        *name = "sandbox-kunpeng-refresh".to_string();
        *group = "kunpeng-config-rpc-sandbox".to_string();
        distinct_group
            .recording
            .background_dependencies
            .push(sandbox);
        distinct_group.validate().unwrap();

        let mut invalid = config;
        let BackgroundDependencyRuleConfig::Motan { method_name, .. } =
            &mut invalid.recording.background_dependencies[0]
        else {
            panic!("expected Motan background rule");
        };
        *method_name = "get*".to_string();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_host_only_or_ambiguous_http_background_rules() {
        let mut config = AppConfig::default();
        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "too-broad".to_string(),
            authorities: vec!["config.api.demo.test".to_string()],
            methods: Vec::new(),
            path_prefixes: vec!["/".to_string()],
            response_role: BackgroundDependencyResponseRole::Independent,
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        assert!(config.validate().is_err());

        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "invalid-path".to_string(),
            authorities: vec!["config.api.demo.test".to_string()],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/lookup?group=x".to_string()],
            response_role: BackgroundDependencyResponseRole::Independent,
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        assert!(config.validate().is_err());

        config.recording.background_dependencies = vec![BackgroundDependencyRuleConfig::Http {
            name: "cross-product".to_string(),
            authorities: vec![
                "config.api.demo.test".to_string(),
                "static.config.api.demo.test".to_string(),
            ],
            methods: vec!["GET".to_string()],
            path_prefixes: vec!["/lookup".to_string()],
            response_role: BackgroundDependencyResponseRole::Independent,
            source_revision: "0123456789abcdef".to_string(),
            source_evidence: "src/config/refresh.rs:42 scheduled refresh".to_string(),
        }];
        assert!(config.validate().is_err());
    }

    #[test]
    fn memcached_runtime_state_requires_ready_probe_and_positive_timeout() {
        let mut config = AppConfig::default();
        config.recording.background_dependencies = vec![memcached_rule(30_000)];
        let error = config.validate().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("require an enabled HTTP gateway ready probe")
        );

        config.http_gateway.enabled = true;
        config.http_gateway.ready.enabled = true;
        config.validate().unwrap();

        config.recording.background_dependencies = vec![memcached_rule(0)];
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("initial_load_timeout_ms"));
    }
}
