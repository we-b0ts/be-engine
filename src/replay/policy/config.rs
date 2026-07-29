use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use super::response::{ResponseRules, response_rule_ids, validate_response_rules};

const MIN_POLICY_VERSION: u8 = 1;
const MAX_POLICY_VERSION: u8 = 2;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct ReplayPolicyDocument {
    pub(in crate::replay) version: u8,
    pub(in crate::replay) expected_response: ExpectedResponseUsage,
    #[serde(default)]
    pub(super) rules: Vec<ReplayPolicyRule>,
    #[serde(default, skip_serializing_if = "ResponseRules::is_empty")]
    pub(in crate::replay) response_rules: ResponseRules,
    #[serde(default)]
    pub(in crate::replay) comparison: ComparisonVerificationPolicy,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedResponseUsage {
    AssertionsOnly,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonSourceMatch {
    #[default]
    Before,
    BeforeOrAfter,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComparisonVerificationPolicy {
    #[serde(default)]
    pub source_match: ComparisonSourceMatch,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(in crate::replay) enum PolicyProtocol {
    Mysql,
    Http,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayPolicyRule {
    pub(super) id: String,
    #[serde(default, rename = "case", skip_serializing_if = "Option::is_none")]
    pub(super) case_selector: Option<CaseSelector>,
    pub(super) protocol: PolicyProtocol,
    #[serde(default)]
    pub(super) target: TargetSelector,
    #[serde(default)]
    pub(super) mysql: Option<MysqlSelector>,
    #[serde(default)]
    pub(super) http: Option<HttpSelector>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MysqlSelector {
    pub(super) command: String,
    pub(super) sql: String,
    #[serde(default)]
    pub(super) database: Option<String>,
    #[serde(default)]
    pub(super) username: Option<String>,
    pub(super) params: BTreeMap<usize, DynamicValueRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpSelector {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) query: BTreeMap<String, DynamicValueRule>,
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
    #[serde(default = "zero_duration")]
    pub(super) offset: String,
    pub(super) tolerance: String,
    #[serde(default)]
    pub(super) format: Option<String>,
    #[serde(default)]
    pub(super) timezone: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TimeReference {
    ReplayNow,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayPolicyValidationReport {
    pub version: u8,
    pub path: String,
    pub fingerprint: String,
    pub expected_response: ExpectedResponseUsage,
    pub comparison: ComparisonVerificationPolicy,
    pub rule_ids: Vec<String>,
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
        comparison: loaded.document.comparison,
        rule_ids: loaded
            .document
            .rules
            .into_iter()
            .map(|rule| rule.id)
            .collect(),
        response_rule_ids,
        runner_owned_response_assertions: loaded.document.version >= 2,
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
    ensure!(
        (MIN_POLICY_VERSION..=MAX_POLICY_VERSION).contains(&document.version),
        "unsupported replay policy version {}; expected {MIN_POLICY_VERSION} or {MAX_POLICY_VERSION}",
        document.version
    );
    ensure!(
        document.version >= 2 || document.response_rules.is_empty(),
        "response_rules require replay policy version 2"
    );
    ensure!(
        document.version >= 2 || document.comparison == ComparisonVerificationPolicy::default(),
        "comparison verification behavior requires replay policy version 2"
    );
    validate_response_rules(&document.response_rules)?;
    let mut ids = BTreeSet::new();
    for rule in &document.rules {
        validate_rule(rule)?;
        ensure!(
            ids.insert(rule.id.as_str()),
            "duplicate replay policy rule id {:?}",
            rule.id
        );
    }
    let bindings = document
        .rules
        .iter()
        .flat_map(dynamic_fields)
        .filter_map(|field| field.bind.as_deref())
        .collect::<BTreeSet<_>>();
    for reference in document
        .rules
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

fn dynamic_fields(rule: &ReplayPolicyRule) -> Vec<&DynamicValueRule> {
    match rule.protocol {
        PolicyProtocol::Mysql => rule
            .mysql
            .as_ref()
            .map(|mysql| mysql.params.values().collect())
            .unwrap_or_default(),
        PolicyProtocol::Http => rule
            .http
            .as_ref()
            .map(|http| http.query.values().collect())
            .unwrap_or_default(),
    }
}

fn validate_rule(rule: &ReplayPolicyRule) -> Result<()> {
    ensure_identifier(&rule.id, "rule id")?;
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
        PolicyProtocol::Mysql => {
            ensure!(
                rule.http.is_none(),
                "MySQL rule {:?} must not define http",
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
                !mysql.params.is_empty(),
                "MySQL rule {:?} must configure at least one params field",
                rule.id
            );
            for (index, field) in &mysql.params {
                validate_dynamic_value(field)
                    .with_context(|| format!("invalid MySQL rule {:?} params[{index}]", rule.id))?;
            }
        }
        PolicyProtocol::Http => {
            ensure!(
                rule.mysql.is_none(),
                "HTTP rule {:?} must not define mysql",
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
                !http.query.is_empty(),
                "HTTP rule {:?} must configure at least one query field",
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
    }
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
        ensure!(
            time.relative_to == TimeReference::ReplayNow,
            "only replay_now is supported"
        );
        parse_duration(&time.offset).context("invalid time.offset")?;
        let tolerance = parse_duration(&time.tolerance).context("invalid time.tolerance")?;
        ensure!(tolerance >= 0, "time.tolerance must not be negative");
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
