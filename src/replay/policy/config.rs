mod mysql;
mod mysql_time;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
mod document;
pub(in crate::replay::policy) use document::BindingEntry;

use super::response::{ResponseRules, response_rule_ids, validate_response_rules};

const MIN_POLICY_VERSION: u8 = 1;
const MAX_POLICY_VERSION: u8 = 3;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    try_from = "document::PolicyDocument",
    into = "document::PolicyDocument"
)]
pub(in crate::replay) struct ReplayPolicyDocument {
    pub(in crate::replay) dynamic_values: Vec<super::dynamic_values::DynamicValueRule>,
    pub(in crate::replay) version: u8,
    pub(in crate::replay) expected_response: ExpectedResponseUsage,
    pub(super) dependency_rules: Vec<ReplayDependencyRule>,
    pub(crate) request_rules: crate::request_rules::RequestRules,
    pub(in crate::replay) response_rules: ResponseRules,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedResponseUsage {
    AssertionsOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(in crate::replay) enum DependencyProtocol {
    Mysql,
    Http,
    Memcached,
    Redis,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayDependencyRule {
    pub(super) id: String,
    #[serde(default, skip_serializing_if = "ReplayScope::is_case")]
    pub(super) replay_scope: ReplayScope,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) source_evidence: String,
    #[serde(default, rename = "case", skip_serializing_if = "Option::is_none")]
    pub(super) case_selector: Option<CaseSelector>,
    pub(super) protocol: DependencyProtocol,
    #[serde(default, skip_serializing_if = "TargetSelector::is_empty")]
    pub(super) target: TargetSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) mysql: Option<MysqlSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) http: Option<HttpSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) memcached: Option<MemcachedSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) redis: Option<super::redis_value::RedisSelector>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayScope {
    #[default]
    Case,
    RecordingRun,
}

impl ReplayScope {
    fn is_case(&self) -> bool {
        *self == Self::Case
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaseSelector {
    pub(super) method: String,
    pub(super) path: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetSelector {
    #[serde(default)]
    pub(super) host: Option<String>,
    #[serde(default)]
    pub(super) port: Option<u16>,
}

impl TargetSelector {
    fn is_empty(&self) -> bool {
        self.host.is_none() && self.port.is_none()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MysqlSelector {
    #[serde(
        default = "mysql::default_command",
        skip_serializing_if = "mysql::is_default_command"
    )]
    pub(super) command: String,
    pub(super) sql: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) table_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) table_series: Option<crate::MysqlTableSeries>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) params: BTreeMap<usize, DynamicValueRule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) sql_values: BTreeMap<usize, MysqlTimeValueRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(try_from = "mysql_time::Config", into = "mysql_time::Config")]
pub(super) enum MysqlTimeValueRule {
    Scalar(MysqlTimeFieldRule),
    Json(BTreeMap<String, MysqlTimeFieldRule>),
}

#[derive(Debug, Clone)]
pub(super) struct MysqlTimeFieldRule {
    pub(super) source_evidence: String,
    pub(super) time: TimeRule,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) multipart: Option<super::request_contract::config::MultipartRule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) headers: BTreeMap<String, super::http_headers::HttpHeaderRule>,
    #[serde(
        default,
        skip_serializing_if = "super::http_json::HttpJsonRules::is_empty"
    )]
    pub(super) json: super::http_json::HttpJsonRules,
    pub(super) method: String,
    pub(super) path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) query: BTreeMap<String, DynamicValueRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemcachedSelector {
    pub(super) resource: MemcachedResourceSelector,
    pub(super) command: String,
    pub(super) key: NumericKeySelector,
    pub(super) protobuf: ProtobufSelector,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum MemcachedResourceSelector {
    CacheService { port: u16 },
}

impl MemcachedResourceSelector {
    pub(super) fn port(&self) -> u16 {
        match self {
            Self::CacheService { port } => *port,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NumericKeySelector {
    #[serde(default)]
    pub(super) prefix: String,
    #[serde(default)]
    pub(super) suffix: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtobufSelector {
    pub(super) timestamp_fields: BTreeMap<u32, ProtobufTimestampFieldRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtobufTimestampFieldRule {
    pub(super) mechanism: ProtobufTimestampMechanism,
    pub(super) source_evidence: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProtobufTimestampMechanism {
    UnixSeconds,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DynamicValueRule {
    #[serde(default)]
    pub(super) bind: Option<String>,
    #[serde(default, rename = "ref")]
    pub(super) reference: Option<String>,
    #[serde(default)]
    pub(super) validate: Option<ValueValidator>,
    #[serde(default)]
    pub(super) time: Option<TimeRule>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ValueValidator {
    NonEmpty,
    Uuid,
    UuidV4,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TimeRule {
    pub(super) relative_to: TimeReference,
    #[serde(default = "zero_duration", skip_serializing)]
    pub(super) offset: String,
    #[serde(
        default = "fixed_time_tolerance",
        skip_serializing_if = "is_fixed_time_tolerance"
    )]
    pub(super) tolerance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) format: Option<String>,
    #[serde(default, skip_serializing)]
    pub(super) timezone: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TimeReference {
    #[serde(alias = "replay_now")]
    PreserveRelative,
}

fn fixed_time_tolerance() -> String {
    "5s".into()
}
fn is_fixed_time_tolerance(value: &str) -> bool {
    value == "5s"
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayPolicyValidationReport {
    pub version: u8,
    pub path: String,
    pub fingerprint: String,
    pub expected_response: ExpectedResponseUsage,
    pub dependency_rule_ids: Vec<String>,
    pub dynamic_value_rule_ids: Vec<String>,
    pub response_rule_ids: Vec<String>,
    pub runner_owned_response_assertions: bool,
}

#[derive(Debug)]
pub(in crate::replay) struct LoadedReplayPolicy {
    pub(in crate::replay) document: ReplayPolicyDocument,
    pub(in crate::replay) path: PathBuf,
    pub(in crate::replay) fingerprint: String,
}

pub fn validate_replay_policy(path: &Path) -> Result<ReplayPolicyValidationReport> {
    let loaded = load_replay_policy(path)?;
    let response_rule_ids = response_rule_ids(&loaded.document.response_rules);
    Ok(ReplayPolicyValidationReport {
        version: loaded.document.version,
        path: loaded.path.display().to_string(),
        fingerprint: loaded.fingerprint,
        expected_response: loaded.document.expected_response,
        dynamic_value_rule_ids: loaded
            .document
            .dynamic_values
            .iter()
            .map(|rule| rule.id.clone())
            .collect(),
        dependency_rule_ids: loaded
            .document
            .dependency_rules
            .into_iter()
            .map(|rule| rule.id)
            .chain(
                loaded
                    .document
                    .dynamic_values
                    .iter()
                    .map(|rule| rule.id.clone()),
            )
            .collect(),
        response_rule_ids,
        runner_owned_response_assertions: loaded.document.version >= 3,
    })
}

pub(in crate::replay) fn load_replay_policy(path: &Path) -> Result<LoadedReplayPolicy> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read replay policy {}", path.display()))?;
    let document: ReplayPolicyDocument = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("failed to parse replay policy {}", path.display()))?;
    validate_document(&document)
        .with_context(|| format!("invalid replay policy {}", path.display()))?;
    let path = path
        .canonicalize()
        .with_context(|| format!("failed to resolve replay policy {}", path.display()))?;
    Ok(LoadedReplayPolicy {
        document,
        path,
        fingerprint: fingerprint(&bytes),
    })
}

pub(super) fn validate_document(document: &ReplayPolicyDocument) -> Result<()> {
    super::dynamic_values::validate(&document.dynamic_values)?;
    ensure!(
        document.version >= 3 || document.dynamic_values.is_empty(),
        "dynamic value rules require policy version 3"
    );
    ensure!(
        matches!(document.version, MIN_POLICY_VERSION | MAX_POLICY_VERSION),
        "unsupported replay policy version {}; expected {MIN_POLICY_VERSION} or {MAX_POLICY_VERSION}",
        document.version
    );
    ensure!(
        document.version >= 3 || document.response_rules.is_empty(),
        "response_rules require replay policy version 3"
    );
    ensure!(
        document.version >= 3 || document.request_rules.is_empty(),
        "request_rules require replay policy version 3"
    );
    document.request_rules.validate()?;
    validate_response_rules(&document.response_rules)?;
    super::request_contract::validate_overlaps(document)?;
    super::redis_value::validate_overlaps(&document.dependency_rules)?;
    super::http_json::validate_overlaps(&document.dependency_rules)?;
    super::http_headers::validate_overlaps(&document.dependency_rules)?;
    let mut ids = document
        .dynamic_values
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    for rule in &document.dependency_rules {
        ensure!(
            document.version >= 3 || rule.replay_scope == ReplayScope::Case,
            "recording_run replay scope requires policy version 3"
        );
        ensure!(
            document.version >= 3 || rule.redis.is_none(),
            "Redis value rules require policy version 3"
        );
        validate_rule(rule)?;
        super::request_contract::validate(rule)?;
        super::http_json::validate(rule)?;
        super::http_headers::validate(rule)?;
        ensure!(
            document.version >= 3 || rule.http.as_ref().is_none_or(|h| h.headers.is_empty()),
            "HTTP header timestamp rules require policy version 3"
        );
        ensure!(
            document.version >= 3 || rule.http.as_ref().is_none_or(|h| h.json.is_empty()),
            "HTTP JSON rules require policy version 3"
        );
        ensure!(
            ids.insert(rule.id.as_str()),
            "duplicate replay policy rule id {:?}",
            rule.id
        );
    }
    let bindings = document
        .dependency_rules
        .iter()
        .flat_map(dynamic_fields)
        .filter_map(|field| field.bind.as_deref())
        .collect::<BTreeSet<_>>();
    for reference in document
        .dependency_rules
        .iter()
        .flat_map(dynamic_fields)
        .filter_map(|field| field.reference.as_deref())
    {
        ensure!(
            bindings.contains(reference),
            "replay policy ref {reference:?} has no bind rule"
        );
    }
    Ok(())
}

fn dynamic_fields(rule: &ReplayDependencyRule) -> Vec<&DynamicValueRule> {
    match rule.protocol {
        DependencyProtocol::Mysql => rule
            .mysql
            .as_ref()
            .map(|mysql| mysql.params.values().collect())
            .unwrap_or_default(),
        DependencyProtocol::Http => rule
            .http
            .as_ref()
            .map(|http| http.query.values().collect())
            .unwrap_or_default(),
        DependencyProtocol::Memcached | DependencyProtocol::Redis => Vec::new(),
    }
}

fn validate_rule(rule: &ReplayDependencyRule) -> Result<()> {
    ensure_identifier(&rule.id, "rule id")?;
    if rule.replay_scope == ReplayScope::RecordingRun {
        ensure!(
            rule.case_selector.is_none(),
            "recording_run scope cannot select a case"
        );
        validate_source_evidence(&rule.source_evidence)?;
        match rule.protocol {
            DependencyProtocol::Http => {
                let http = rule
                    .http
                    .as_ref()
                    .context("recording_run scope requires HTTP selector")?;
                crate::replay::http_cross_case::HttpCrossCaseSelector {
                    host: rule.target.host.clone().unwrap_or_default(),
                    port: rule.target.port.unwrap_or_default(),
                    method: http.method.clone(),
                    path: http.path.clone(),
                }
                .validate()?;
                ensure!(
                    http.query.is_empty(),
                    "cross-case requires exact query matching; dynamic query rules are not supported"
                );
            }
            DependencyProtocol::Redis => {
                ensure!(
                    matches!(
                        rule.redis.as_ref(),
                        Some(super::redis_value::RedisSelector::TimeShift(_))
                    ),
                    "Redis recording_run scope requires a GET/HGET time-shift selector"
                );
            }
            _ => anyhow::bail!("recording_run scope supports only HTTP and Redis"),
        }
    } else {
        ensure!(
            rule.source_evidence.is_empty() || super::request_contract::is_request_rule(rule),
            "dependency source_evidence requires recording_run scope"
        );
    }
    if let Some(case) = &rule.case_selector {
        ensure!(
            !case.method.trim().is_empty(),
            "rule {:?} case.method must not be empty",
            rule.id
        );
        ensure!(
            case.path.starts_with('/'),
            "rule {:?} case.path must be an absolute HTTP path pattern",
            rule.id
        );
    }
    if rule.target.port.is_some() {
        ensure!(
            rule.target.host.is_some(),
            "rule {:?} target.port requires target.host",
            rule.id
        );
    }
    match rule.protocol {
        DependencyProtocol::Mysql => {
            ensure!(
                rule.http.is_none() && rule.memcached.is_none(),
                "MySQL rule {:?} must not define http or memcached",
                rule.id
            );
            let mysql = rule
                .mysql
                .as_ref()
                .with_context(|| format!("MySQL rule {:?} requires mysql", rule.id))?;
            ensure!(
                !mysql.command.trim().is_empty() && !mysql.sql.trim().is_empty(),
                "MySQL rule {:?} requires non-empty command and sql",
                rule.id
            );
            ensure!(
                rule.target.host.is_some() || mysql.database.is_some() || mysql.username.is_some(),
                "MySQL rule {:?} must select target.host, database, or username",
                rule.id
            );
            ensure!(
                !mysql.params.is_empty() || !mysql.sql_values.is_empty(),
                "MySQL rule {:?} must configure at least one params or sql_values field",
                rule.id
            );
            if !mysql.sql_values.is_empty() {
                mysql::validate_selector(mysql)?;
            } else {
                ensure!(
                    mysql.tables.is_empty()
                        && mysql.table_patterns.is_empty()
                        && mysql.table_series.is_none(),
                    "MySQL table templates require sql_values"
                );
            }
            for (index, field) in &mysql.params {
                validate_dynamic_value(field)
                    .with_context(|| format!("invalid MySQL rule {:?} params[{index}]", rule.id))?;
            }
        }
        DependencyProtocol::Http => {
            ensure!(
                rule.mysql.is_none() && rule.memcached.is_none(),
                "HTTP rule {:?} must not define mysql or memcached",
                rule.id
            );
            ensure!(
                rule.target.host.is_some(),
                "HTTP rule {:?} requires target.host",
                rule.id
            );
            let http = rule
                .http
                .as_ref()
                .with_context(|| format!("HTTP rule {:?} requires http", rule.id))?;
            ensure!(
                !http.method.trim().is_empty() && http.path.starts_with('/'),
                "HTTP rule {:?} requires a method and absolute dependency path",
                rule.id
            );
            ensure!(
                !http.query.is_empty()
                    || !http.headers.is_empty()
                    || !http.json.is_empty()
                    || http.multipart.is_some()
                    || rule.replay_scope == ReplayScope::RecordingRun,
                "HTTP rule {:?} must configure query fields, JSON rules, header rules or recording_run scope",
                rule.id
            );
            for (name, field) in &http.query {
                ensure!(
                    !name.trim().is_empty(),
                    "HTTP rule {:?} contains an empty query field name",
                    rule.id
                );
                validate_dynamic_value(field)
                    .with_context(|| format!("invalid HTTP rule {:?} query.{name}", rule.id))?;
            }
        }
        DependencyProtocol::Redis => super::redis_value::validate(rule)?,
        DependencyProtocol::Memcached => {
            ensure!(
                rule.mysql.is_none() && rule.http.is_none(),
                "Memcached rule {:?} must not define mysql or http",
                rule.id
            );
            ensure!(
                rule.target.host.is_none() && rule.target.port.is_none(),
                "Memcached rule {:?} must select its resource under memcached.resource, not target",
                rule.id
            );
            let memcached = rule
                .memcached
                .as_ref()
                .with_context(|| format!("Memcached rule {:?} requires memcached", rule.id))?;
            ensure!(
                memcached.resource.port() != 0,
                "Memcached rule {:?} cache_service resource port must be greater than zero",
                rule.id
            );
            ensure!(
                memcached.command == "set",
                "Memcached rule {:?} currently supports only command \"set\"",
                rule.id
            );
            ensure!(
                !memcached.key.prefix.is_empty() || !memcached.key.suffix.is_empty(),
                "Memcached rule {:?} numeric key selector requires a prefix or suffix",
                rule.id
            );
            ensure!(
                memcached
                    .key
                    .prefix
                    .len()
                    .checked_add(memcached.key.suffix.len())
                    .is_some_and(|len| len < 250),
                "Memcached rule {:?} numeric key selector leaves no room for a numeric middle",
                rule.id
            );
            ensure!(
                memcached.protobuf.timestamp_fields.len() <= 32,
                "Memcached rule {:?} selects more than 32 protobuf timestamp fields",
                rule.id
            );
            ensure!(
                !memcached.protobuf.timestamp_fields.is_empty(),
                "Memcached rule {:?} requires at least one protobuf timestamp field",
                rule.id
            );
            for (number, field) in &memcached.protobuf.timestamp_fields {
                ensure!(
                    (1..(1_u32 << 29)).contains(number),
                    "Memcached rule {:?} protobuf field number {number} is invalid",
                    rule.id
                );
                ensure!(
                    field.mechanism == ProtobufTimestampMechanism::UnixSeconds,
                    "Memcached rule {:?} protobuf field {number} uses an unsupported timestamp mechanism",
                    rule.id
                );
                validate_source_evidence(&field.source_evidence).with_context(|| {
                    format!(
                        "invalid Memcached rule {:?} protobuf timestamp field {number}",
                        rule.id
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn validate_source_evidence(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.trim() == value,
        "source_evidence must be non-empty and trimmed"
    );
    ensure!(
        value.len() <= 1024 && !value.contains(['\r', '\n']),
        "source_evidence must be one line of at most 1024 bytes"
    );
    Ok(())
}

fn validate_dynamic_value(rule: &DynamicValueRule) -> Result<()> {
    ensure!(
        rule.bind.is_some()
            || rule.reference.is_some()
            || rule.validate.is_some()
            || rule.time.is_some(),
        "dynamic field requires bind, ref, validate, or time"
    );
    ensure!(
        !(rule.bind.is_some() && rule.reference.is_some()),
        "bind and ref are mutually exclusive"
    );
    if let Some(reference) = &rule.reference {
        ensure_identifier(reference, "ref")?;
        ensure!(
            rule.validate.is_none() && rule.time.is_none(),
            "ref cannot be combined with validate or time"
        );
    }
    if let Some(binding) = &rule.bind {
        ensure_identifier(binding, "bind")?;
    }
    ensure!(
        !(rule.validate.is_some() && rule.time.is_some()),
        "validate and time are mutually exclusive"
    );
    if let Some(time) = &rule.time {
        parse_duration(&time.offset).context("invalid time.offset")?;
        let tolerance = parse_duration(&time.tolerance).context("invalid time.tolerance")?;
        ensure!(tolerance == 5_000, "time tolerance is fixed at 5s");
        if let Some(timezone) = &time.timezone {
            parse_timezone(timezone)?;
        }
    }
    Ok(())
}

fn ensure_identifier(value: &str, name: &str) -> Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        bail!("{name} must not be empty");
    };
    ensure!(
        first.is_ascii_alphabetic() || first == '_',
        "{name} must start with an ASCII letter or underscore"
    );
    ensure!(
        chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')),
        "{name} contains unsupported characters"
    );
    Ok(())
}

pub(super) fn parse_duration(value: &str) -> Result<i64> {
    let value = value.trim();
    ensure!(!value.is_empty(), "duration must not be empty");
    let split = value
        .find(|ch: char| ch.is_ascii_alphabetic())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    let amount = amount
        .parse::<i64>()
        .with_context(|| format!("invalid duration amount {amount:?}"))?;
    let multiplier = match unit {
        "ms" => 1_i64,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => bail!("unsupported duration unit {unit:?}; use ms, s, m, h, or d"),
    };
    amount
        .checked_mul(multiplier)
        .context("duration is out of range")
}

pub(super) fn parse_timezone(value: &str) -> Result<i32> {
    let bytes = value.as_bytes();
    ensure!(
        bytes.len() == 6 && matches!(bytes[0], b'+' | b'-') && bytes[3] == b':',
        "timezone must use +HH:MM or -HH:MM"
    );
    ensure!(
        [bytes[1], bytes[2], bytes[4], bytes[5]]
            .into_iter()
            .all(|byte| byte.is_ascii_digit()),
        "timezone must use numeric hours and minutes"
    );
    let hours = value[1..3]
        .parse::<i32>()
        .context("invalid timezone hour")?;
    let minutes = value[4..6]
        .parse::<i32>()
        .context("invalid timezone minute")?;
    ensure!(hours <= 23 && minutes <= 59, "timezone is out of range");
    let seconds = hours * 3_600 + minutes * 60;
    Ok(if bytes[0] == b'-' { -seconds } else { seconds })
}

fn zero_duration() -> String {
    "0s".to_string()
}

pub(in crate::replay) fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}
