mod matching;
pub mod mysql;
pub mod publish;
pub mod pubsub;
mod redis;
pub use mysql::{MysqlBackgroundSelector, MysqlBackgroundTableSeries};

use std::collections::HashSet;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hyper::http::{Method, Uri, uri::Authority};
use serde::{Deserialize, Serialize};

use crate::protocols::recording::events::RecorderEvent;

const MAX_HTTP_AUTHORITIES: usize = 64;
const MAX_HTTP_PATH_PREFIXES: usize = 64;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedisKeyPatternConfig {
    pub prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub suffix: String,
    #[serde(default)]
    pub numeric_middle: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackgroundDependencyRuleConfig {
    RedisPublish {
        name: String,
        selector: publish::Selector,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
    RedisPubsub {
        name: String,
        selector: crate::policy::native::RedisPubsubSelector,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
    Mysql {
        #[serde(default, skip_serializing_if = "super::api_trigger::mysql::disabled")]
        include_transaction_boundaries: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        transaction_members: Vec<MysqlBackgroundSelector>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger_source: Option<super::api_trigger::ApiTriggerSource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_value_index: Option<usize>,
        name: String,
        selector: MysqlBackgroundSelector,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
    Http {
        name: String,
        authorities: Vec<String>,
        methods: Vec<String>,
        path_prefixes: Vec<String>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
    Memcached {
        name: String,
        breeze_identity: String,
        command: String,
        key_start: u64,
        key_end: u64,
        key_separator: String,
        key_suffix: String,
        initial_load_timeout_ms: u64,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
    Redis {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_sequence: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        script: Option<super::api_trigger::redis_script::ApiTriggerRedisScript>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger_source: Option<super::api_trigger::ApiTriggerSource>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_templates: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        arguments: Vec<String>,
        name: String,
        ports: Vec<u16>,
        command: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        key_patterns: Vec<RedisKeyPatternConfig>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        key_prefix: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        key_suffix: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_load_timeout_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
    Motan {
        name: String,
        group: String,
        interface_name: String,
        method_name: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        source_revision: String,
        source_evidence: String,
    },
}

impl BackgroundDependencyRuleConfig {
    pub fn trigger_source(&self) -> Option<&super::api_trigger::ApiTriggerSource> {
        match self {
            Self::Redis { trigger_source, .. } | Self::Mysql { trigger_source, .. } => {
                trigger_source.as_ref()
            }
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Mysql { name, .. }
            | Self::Http { name, .. }
            | Self::Memcached { name, .. }
            | Self::Redis { name, .. }
            | Self::RedisPubsub { name, .. }
            | Self::RedisPublish { name, .. }
            | Self::Motan { name, .. } => name,
        }
    }

    pub fn matches(&self, event: &RecorderEvent) -> bool {
        matching::matches(self, event)
    }

    /// Only an explicit initial-load contract authorizes reusable snapshot reads.
    /// A process owner alone never changes a finite dependency into a cache.
    pub fn uses_redis_snapshot(&self) -> bool {
        matches!(
            self,
            Self::Redis {
                initial_load_timeout_ms: Some(_),
                trigger_source: None,
                ..
            }
        )
    }
}

pub fn validate(rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for rule in rules {
        let name = rule.name();
        if name.trim().is_empty() {
            bail!("process-owned dependency rule name must not be empty");
        }
        if !names.insert(name) {
            bail!("duplicate process-owned dependency rule name {name:?}");
        }
        match rule {
            BackgroundDependencyRuleConfig::RedisPublish {
                selector,
                source_revision,
                source_evidence,
                ..
            } => {
                selector.validate(name)?;
                if !source_revision.is_empty() {
                    validate_source_revision(source_revision)?;
                }
                validate_optional_source_evidence(source_evidence)?;
            }
            BackgroundDependencyRuleConfig::RedisPubsub {
                selector,
                source_revision,
                source_evidence,
                ..
            } => {
                pubsub::validate(selector)?;
                if !source_revision.is_empty() {
                    validate_source_revision(source_revision)?;
                }
                validate_optional_source_evidence(source_evidence)?;
            }
            BackgroundDependencyRuleConfig::Mysql {
                selector,
                source_revision,
                source_evidence,
                ..
            } => {
                if rule.trigger_source().is_some() {
                    selector.validate_api()?;
                } else {
                    selector.validate()?;
                }
                super::api_trigger::mysql::validate(rule)?;
                if rule.trigger_source().is_some() || !source_revision.is_empty() {
                    validate_source_revision(source_revision)?;
                }
                validate_optional_source_evidence(source_evidence)?;
            }
            BackgroundDependencyRuleConfig::Http {
                authorities,
                methods,
                path_prefixes,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_authorities(name, authorities)?;
                validate_methods(name, methods)?;
                validate_path_prefixes(name, path_prefixes)?;
                if !source_revision.is_empty() {
                    validate_source_revision(source_revision)?;
                }
                validate_optional_source_evidence(source_evidence)?;
            }
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity,
                command,
                key_start,
                key_end,
                key_separator,
                key_suffix,
                initial_load_timeout_ms,
                source_revision,
                source_evidence,
                ..
            } => {
                validate_breeze_identity(name, breeze_identity)?;
                if command != "get" {
                    bail!(
                        "Memcached process-owned dependency rule {name:?} currently supports only command \"get\""
                    );
                }
                validate_key_series(name, *key_start, *key_end, key_separator, key_suffix)?;
                if *initial_load_timeout_ms == 0 {
                    bail!(
                        "Memcached process-owned dependency rule {name:?} initial_load_timeout_ms must be greater than zero"
                    );
                }
                if !source_revision.is_empty() {
                    validate_source_revision(source_revision)?;
                }
                validate_optional_source_evidence(source_evidence)?;
            }
            BackgroundDependencyRuleConfig::Redis { .. } => redis::validate(rule)?,
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
                        "Motan heartbeat is protocol-owned and cannot be configured as a process-owned dependency rule"
                    );
                }
                if !source_revision.is_empty() {
                    validate_source_revision(source_revision)?;
                }
                validate_optional_source_evidence(source_evidence)?;
            }
        }
    }
    validate_api_origin_selector_conflicts(rules)?;
    Ok(())
}

fn validate_source_revision(source_revision: &str) -> Result<()> {
    // Image fingerprints arrive as `sha256:<hex>`; the recorded hex digest is
    // the revision, so accept the digest after stripping the algorithm tag.
    let source_revision = source_revision
        .strip_prefix("sha256:")
        .unwrap_or(source_revision);
    validate_single_line(
        "process-owned dependency source revision",
        source_revision,
        64,
    )?;
    if source_revision.len() < 7
        || !source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!(
            "process-owned dependency source revision must be a 7-64 character lowercase hexadecimal revision"
        );
    }
    Ok(())
}

/// Runtime DTOs may omit plan-only evidence. Explicit evidence, when present,
/// retains the same bounded representation; authoring plans use the strict owner.
pub use traffic_policy_schema::evidence::{
    validate_optional_source_evidence, validate_source_evidence,
};

fn validate_api_origin_selector_conflicts(rules: &[BackgroundDependencyRuleConfig]) -> Result<()> {
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            // Process selectors are observations of a whole Source task. Their
            // complete actual match set decides ownership at request admission;
            // cross-task overlap remains first-class unattributed evidence.
            // API-origin identity/order contracts retain their strict conflicts.
            if left.trigger_source().is_none() && right.trigger_source().is_none() {
                continue;
            }
            if rules_overlap(left, right) {
                bail!(
                    "process-owned dependency rules {:?} and {:?} have overlapping selectors",
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
    if let Some(overlap) = super::api_trigger::overlap(left, right) {
        return overlap;
    }

    match (left, right) {
        (
            BackgroundDependencyRuleConfig::RedisPubsub { selector: left, .. },
            BackgroundDependencyRuleConfig::RedisPubsub {
                selector: right, ..
            },
        ) => left == right,
        (
            BackgroundDependencyRuleConfig::Mysql { selector: left, .. },
            BackgroundDependencyRuleConfig::Mysql {
                selector: right, ..
            },
        ) => left.overlaps(right),
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
                right_authorities.iter().any(|right| {
                    matching::authority_matches(left, right)
                        || matching::authority_matches(right, left)
                })
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
                keys: left_keys,
                key_patterns: left_patterns,
                key_prefix: left_prefix,
                key_suffix: left_suffix,
                fields: left_fields,
                ..
            },
            BackgroundDependencyRuleConfig::Redis {
                ports: right_ports,
                command: right_command,
                keys: right_keys,
                key_patterns: right_patterns,
                key_prefix: right_prefix,
                key_suffix: right_suffix,
                fields: right_fields,
                ..
            },
        ) => {
            left_ports.iter().any(|port| right_ports.contains(port))
                && left_command == right_command
                && left_fields == right_fields
                && if !left_patterns.is_empty() || !right_patterns.is_empty() {
                    true
                } else if left_keys.is_empty() && right_keys.is_empty() {
                    byte_affixes_overlap(
                        left_prefix.as_bytes(),
                        left_suffix.as_bytes(),
                        right_prefix.as_bytes(),
                        right_suffix.as_bytes(),
                    )
                } else {
                    left_keys.iter().any(|key| right_keys.contains(key))
                }
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
        bail!(
            "Redis process-owned dependency rule {rule_name:?} must include between 1 and 64 ports"
        );
    }
    let mut unique = HashSet::new();
    for port in ports {
        if *port == 0 {
            bail!("Redis process-owned dependency rule {rule_name:?} port must be nonzero");
        }
        if !unique.insert(*port) {
            bail!("Redis process-owned dependency rule {rule_name:?} has duplicate port {port}");
        }
    }
    Ok(())
}

fn validate_exact_redis_keys(rule_name: &str, command: &str, keys: &[String]) -> Result<()> {
    const MAX_KEYS: usize = 4_096;
    if keys.is_empty() || keys.len() > MAX_KEYS {
        bail!(
            "Redis {command} process-owned dependency rule {rule_name:?} must include between 1 and {MAX_KEYS} exact keys"
        );
    }
    let mut unique = HashSet::new();
    for key in keys {
        validate_single_line(
            &format!("Redis {command} process-owned dependency key"),
            key,
            512,
        )?;
        if !unique.insert(key) {
            bail!(
                "Redis {command} process-owned dependency rule {rule_name:?} has duplicate key {key:?}"
            );
        }
    }
    Ok(())
}

fn validate_redis_key_selectors(
    rule_name: &str,
    command: &str,
    keys: &[String],
    patterns: &[RedisKeyPatternConfig],
) -> Result<()> {
    if keys.is_empty() && patterns.is_empty() {
        bail!(
            "Redis {command} process-owned dependency rule {rule_name:?} must include at least one exact key or key pattern"
        );
    }
    if !keys.is_empty() {
        validate_exact_redis_keys(rule_name, command, keys)?;
    }
    if patterns.len() > 64 {
        bail!(
            "Redis {command} process-owned dependency rule {rule_name:?} must include at most 64 key patterns"
        );
    }
    let mut unique = HashSet::new();
    for pattern in patterns {
        validate_single_line(
            &format!("Redis {command} process-owned dependency key-pattern prefix"),
            &pattern.prefix,
            512,
        )?;
        if !pattern.suffix.is_empty() {
            validate_single_line(
                &format!("Redis {command} process-owned dependency key-pattern suffix"),
                &pattern.suffix,
                512,
            )?;
        }
        if !pattern.numeric_middle {
            bail!(
                "Redis {command} process-owned dependency rule {rule_name:?} key patterns must require a numeric middle"
            );
        }
        if !unique.insert((
            pattern.prefix.as_str(),
            pattern.suffix.as_str(),
            pattern.numeric_middle,
        )) {
            bail!(
                "Redis {command} process-owned dependency rule {rule_name:?} has a duplicate key pattern"
            );
        }
    }
    Ok(())
}

fn validate_redis_hash_fields(rule_name: &str, command: &str, fields: &[String]) -> Result<()> {
    let valid_count = if command == "HGET" {
        fields.len() == 1
    } else {
        !fields.is_empty() && fields.len() <= 64
    };
    if !valid_count {
        bail!(
            "Redis {command} process-owned dependency rule {rule_name:?} has an invalid exact field shape"
        );
    }
    for field in fields {
        validate_single_line(
            &format!("Redis {command} process-owned dependency field"),
            field,
            512,
        )?;
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
        &format!("Motan process-owned dependency {field}"),
        value,
        max_len,
    )?;
    if value.contains(['*', '#']) {
        bail!(
            "Motan process-owned dependency rule {rule_name:?} {field} must be exact and cannot contain wildcards or '#'"
        );
    }
    Ok(())
}

fn validate_breeze_identity(rule_name: &str, identity: &str) -> Result<()> {
    validate_single_line(
        "Memcached process-owned dependency Breeze identity",
        identity,
        1_024,
    )?;
    let fields = identity.split('@').collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
        bail!(
            "Memcached process-owned dependency rule {rule_name:?} must use a stable service@socket-type@protocol Breeze identity"
        );
    }
    if fields[1] != "mc" {
        bail!(
            "Memcached process-owned dependency rule {rule_name:?} requires a Breeze mc socket identity"
        );
    }
    if fields[1].contains(':') {
        bail!(
            "Memcached process-owned dependency rule {rule_name:?} must not persist a Breeze port"
        );
    }
    Ok(())
}

fn validate_key_series(
    rule_name: &str,
    start: u64,
    end: u64,
    separator: &str,
    suffix: &str,
) -> Result<()> {
    const MAX_KEYS: u64 = 65_536;
    if start > end {
        bail!(
            "Memcached process-owned dependency rule {rule_name:?} key_start must not exceed key_end"
        );
    }
    if u128::from(end) - u128::from(start) + 1 > u128::from(MAX_KEYS) {
        bail!(
            "Memcached process-owned dependency rule {rule_name:?} exceeds the {MAX_KEYS} key safety limit"
        );
    }
    if separator.len() != 1
        || !separator.is_ascii()
        || separator.as_bytes()[0].is_ascii_alphanumeric()
    {
        bail!(
            "Memcached process-owned dependency rule {rule_name:?} key_separator must be one non-alphanumeric ASCII byte"
        );
    }
    validate_single_line("Memcached process-owned dependency key suffix", suffix, 128)?;
    Ok(())
}

pub fn matches_memcached_key_series(
    key: &[u8],
    start: u64,
    end: u64,
    separator: u8,
    suffix: &[u8],
) -> bool {
    let Some(separator_index) = key.iter().position(|byte| *byte == separator) else {
        return false;
    };
    let (prefix, actual_suffix) = key.split_at(separator_index);
    if prefix.is_empty()
        || prefix.len() > 20
        || prefix.iter().any(|byte| !byte.is_ascii_digit())
        || actual_suffix.get(1..) != Some(suffix)
    {
        return false;
    }
    let Ok(prefix) = std::str::from_utf8(prefix) else {
        return false;
    };
    let Ok(value) = prefix.parse::<u64>() else {
        return false;
    };
    value >= start && value <= end && value.to_string() == prefix
}

pub fn redis_rule_matches(
    rule: &BackgroundDependencyRuleConfig,
    target_port: u16,
    command: &str,
    args: &[Vec<u8>],
) -> bool {
    if rule.trigger_source().is_some() {
        return false;
    }

    if let BackgroundDependencyRuleConfig::RedisPublish { selector, .. } = rule {
        return selector.matches(target_port, command, args);
    }
    let BackgroundDependencyRuleConfig::Redis {
        ports,
        command: expected_command,
        keys,
        key_patterns,
        key_prefix,
        key_suffix,
        fields,
        ..
    } = rule
    else {
        return false;
    };
    let Some(key) = args.first() else {
        return false;
    };
    let key_matches = if !key_patterns.is_empty() {
        matches_exact_redis_key(key, keys)
            || key_patterns.iter().any(|pattern| {
                matches_redis_numeric_key_pattern(
                    key,
                    pattern.prefix.as_bytes(),
                    pattern.suffix.as_bytes(),
                )
            })
    } else if keys.is_empty() {
        matches_redis_key(key, key_prefix.as_bytes(), key_suffix.as_bytes())
    } else {
        matches_exact_redis_key(key, keys)
    };
    ports.contains(&target_port)
        && expected_command.eq_ignore_ascii_case(command)
        && (!expected_command.eq_ignore_ascii_case("SET") || args.len() >= 2)
        && key_matches
        && (fields.is_empty()
            || args[1..]
                .iter()
                .map(Vec::as_slice)
                .eq(fields.iter().map(|field| field.as_bytes())))
}

pub fn matches_exact_redis_key(key: &[u8], keys: &[String]) -> bool {
    keys.iter().any(|candidate| candidate.as_bytes() == key)
}

fn decode_capture(capture: &crate::recorder::BodyCapture) -> Option<Vec<u8>> {
    if capture.truncated {
        return None;
    }
    match capture.encoding {
        "utf8" => Some(capture.data.as_bytes().to_vec()),
        "base64" => STANDARD.decode(capture.data.as_bytes()).ok(),
        _ => None,
    }
}

fn validate_authorities(rule_name: &str, authorities: &[String]) -> Result<()> {
    if authorities.is_empty() || authorities.len() > MAX_HTTP_AUTHORITIES {
        bail!(
            "HTTP process-owned dependency rule {rule_name:?} must include between 1 and {MAX_HTTP_AUTHORITIES} authorities"
        );
    }
    let mut unique = HashSet::new();
    for authority in authorities {
        let normalized = normalize_authority(authority).ok_or_else(|| {
            anyhow::anyhow!(
                "HTTP process-owned dependency rule {rule_name:?} has invalid authority {authority:?}"
            )
        })?;
        if !unique.insert(normalized) {
            bail!(
                "HTTP process-owned dependency rule {rule_name:?} has duplicate authority {authority:?}"
            );
        }
    }
    Ok(())
}

fn validate_methods(rule_name: &str, methods: &[String]) -> Result<()> {
    if methods.len() != 1 {
        bail!("HTTP process-owned dependency rule {rule_name:?} must include exactly one method");
    }
    let mut unique = HashSet::new();
    for method in methods {
        let parsed = method.parse::<Method>().map_err(|_| {
            anyhow::anyhow!(
                "HTTP process-owned dependency rule {rule_name:?} has invalid method {method:?}"
            )
        })?;
        let normalized = parsed.as_str().to_ascii_uppercase();
        if !unique.insert(normalized) {
            bail!(
                "HTTP process-owned dependency rule {rule_name:?} has duplicate method {method:?}"
            );
        }
    }
    Ok(())
}

fn validate_path_prefixes(rule_name: &str, path_prefixes: &[String]) -> Result<()> {
    if path_prefixes.is_empty() || path_prefixes.len() > MAX_HTTP_PATH_PREFIXES {
        bail!(
            "HTTP process-owned dependency rule {rule_name:?} must include between 1 and {MAX_HTTP_PATH_PREFIXES} path prefixes"
        );
    }
    let mut unique = HashSet::new();
    for prefix in path_prefixes {
        if !prefix.starts_with('/') || prefix.contains('?') || prefix.contains('#') {
            bail!(
                "HTTP process-owned dependency rule {rule_name:?} has invalid path prefix {prefix:?}"
            );
        }
        if !unique.insert(prefix) {
            bail!(
                "HTTP process-owned dependency rule {rule_name:?} has duplicate path prefix {prefix:?}"
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

use traffic_policy_schema::evidence::validate_single_line;

#[cfg(test)]
#[path = "process_owned_dependencies/redis_tests.rs"]
mod redis_tests;

#[cfg(test)]
#[path = "process_owned_dependencies/tests.rs"]
mod tests;

pub use traffic_protocol_redis::keys::{matches_redis_key, matches_redis_numeric_key_pattern};
