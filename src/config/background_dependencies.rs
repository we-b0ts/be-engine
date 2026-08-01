use std::collections::HashSet;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
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
    Redis {
        name: String,
        ports: Vec<u16>,
        command: String,
        key_prefix: String,
        key_suffix: String,
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
            Self::Http { name, .. }
            | Self::Memcached { name, .. }
            | Self::Redis { name, .. }
            | Self::Motan { name, .. } => name,
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
                Self::Redis {
                    ports,
                    command,
                    key_prefix,
                    key_suffix,
                    ..
                },
                RecorderEvent::RedisExchange(exchange),
            ) => {
                !exchange.session_setup
                    && exchange.replay_safe
                    && ports.contains(&exchange.target_port)
                    && exchange.command.eq_ignore_ascii_case(command)
                    && exchange.args.first().is_some_and(|key| {
                        capture_matches_redis_key(key, key_prefix.as_bytes(), key_suffix.as_bytes())
                    })
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
            BackgroundDependencyRuleConfig::Redis {
                ports,
                command,
                key_prefix,
                key_suffix,
                response_role,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_redis_ports(name, ports)?;
                if command != "ZCOUNT" {
                    bail!(
                        "Redis background dependency rule {name:?} currently supports only command \"ZCOUNT\""
                    );
                }
                validate_single_line("Redis background dependency key prefix", key_prefix, 512)?;
                validate_single_line("Redis background dependency key suffix", key_suffix, 512)?;
                if *response_role != BackgroundDependencyResponseRole::Independent {
                    bail!(
                        "Redis background dependency rule {name:?} must use response_role = \"independent\""
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
            BackgroundDependencyRuleConfig::Redis {
                ports: left_ports,
                command: left_command,
                key_prefix: left_prefix,
                key_suffix: left_suffix,
                ..
            },
            BackgroundDependencyRuleConfig::Redis {
                ports: right_ports,
                command: right_command,
                key_prefix: right_prefix,
                key_suffix: right_suffix,
                ..
            },
        ) => {
            left_ports.iter().any(|port| right_ports.contains(port))
                && left_command == right_command
                && byte_affixes_overlap(
                    left_prefix.as_bytes(),
                    left_suffix.as_bytes(),
                    right_prefix.as_bytes(),
                    right_suffix.as_bytes(),
                )
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

fn validate_redis_ports(rule_name: &str, ports: &[u16]) -> Result<()> {
    if ports.is_empty() || ports.len() > 64 {
        bail!("Redis background dependency rule {rule_name:?} must include between 1 and 64 ports");
    }
    let mut unique = HashSet::new();
    for port in ports {
        if *port == 0 {
            bail!("Redis background dependency rule {rule_name:?} port must be nonzero");
        }
        if !unique.insert(*port) {
            bail!("Redis background dependency rule {rule_name:?} has duplicate port {port}");
        }
    }
    Ok(())
}

fn byte_affixes_overlap(
    left_prefix: &[u8],
    left_suffix: &[u8],
    right_prefix: &[u8],
    right_suffix: &[u8],
) -> bool {
    (left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix))
        && (left_suffix.ends_with(right_suffix) || right_suffix.ends_with(left_suffix))
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

pub(crate) fn matches_redis_key(key: &[u8], prefix: &[u8], suffix: &[u8]) -> bool {
    key.starts_with(prefix) && key.ends_with(suffix)
}

fn capture_matches_redis_key(
    capture: &crate::recorder::BodyCapture,
    prefix: &[u8],
    suffix: &[u8],
) -> bool {
    if capture.truncated {
        return false;
    }
    match capture.encoding {
        "utf8" => matches_redis_key(capture.data.as_bytes(), prefix, suffix),
        "base64" => STANDARD
            .decode(capture.data.as_bytes())
            .is_ok_and(|key| matches_redis_key(&key, prefix, suffix)),
        _ => false,
    }
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
#[path = "background_dependencies/redis_tests.rs"]
mod redis_tests;

#[cfg(test)]
#[path = "background_dependencies/tests.rs"]
mod tests;
