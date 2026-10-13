//! Explicit API origins and bounded identity selectors for process traffic.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::mysql_tables::TableMatcher;
use super::process_owned_dependencies::BackgroundDependencyRuleConfig;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTriggerSource {
    pub kind: ApiTriggerKind,
    pub method: String,
    pub path: String,
    /// JSON Pointer -> typed scalar in the inbound request body, never query/response.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_body_json: BTreeMap<String, Value>,
    /// Version one admits exactly one integer identity captured from one INSERT.
    pub capture: BTreeMap<String, ApiTriggerCapture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiTriggerKind {
    Api,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTriggerCapture {
    pub protocol: ApiCaptureProtocol,
    pub target_host: String,
    pub target_port: u16,
    pub database: String,
    pub username: String,
    pub operation: ApiCaptureOperation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    pub row_match: BTreeMap<String, Value>,
    pub column: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCaptureProtocol {
    Mysql,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiCaptureOperation {
    #[serde(rename = "INSERT")]
    Insert,
}

impl ApiTriggerSource {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.method.parse::<hyper::Method>().is_ok()
                && self.method == self.method.to_ascii_uppercase(),
            "trigger_source.method must be an uppercase HTTP method"
        );
        ensure!(
            self.path.starts_with('/')
                && !self.path.contains(['?', '#', '*'])
                && self.path.len() <= 1024
                && self.path.parse::<hyper::Uri>().is_ok(),
            "trigger_source.path must be an exact HTTP path without query or wildcard"
        );
        ensure!(
            self.request_body_json.len() <= 16,
            "too many request_body_json conditions"
        );
        for (pointer, value) in &self.request_body_json {
            ensure!(
                valid_pointer(pointer),
                "request_body_json requires JSON Pointers, for example /background"
            );
            ensure!(
                scalar(value),
                "request_body_json requires typed non-null scalar values"
            );
        }
        ensure!(
            self.capture.len() == 1,
            "trigger_source requires exactly one identity capture"
        );
        let (name, capture) = self.capture.iter().next().expect("one capture");
        ensure!(identifier(name), "invalid trigger identity name");
        capture.validate()
    }

    pub(crate) fn binding(&self) -> (&str, &ApiTriggerCapture) {
        let (name, capture) = self.capture.iter().next().expect("validated capture");
        (name, capture)
    }
}

impl ApiTriggerCapture {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.target_host.is_empty()
                && self.target_host.len() <= 253
                && self
                    .target_host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
                && self.target_port > 0,
            "trigger capture requires an exact MySQL host and nonzero port"
        );
        ensure!(
            identifier(&self.database) && identifier(&self.username) && identifier(&self.column),
            "trigger capture database, username and column must be bounded identifiers"
        );
        TableMatcher::new(&self.tables, &self.table_patterns, None)?;
        ensure!(
            !self.row_match.is_empty() && self.row_match.len() <= 16,
            "trigger INSERT capture requires bounded row_match predicates"
        );
        ensure!(
            self.row_match
                .iter()
                .all(|(key, value)| identifier(key) && scalar(value) && !value.is_boolean()),
            "trigger row_match requires columns and typed string or numeric literal values"
        );
        Ok(())
    }
}

pub(crate) fn validate_redis(rule: &BackgroundDependencyRuleConfig) -> Result<()> {
    let BackgroundDependencyRuleConfig::Redis {
        trigger_source: Some(source),
        key_templates,
        arguments,
        command,
        keys,
        key_patterns,
        key_prefix,
        key_suffix,
        initial_load_timeout_ms,
        fields,
        ..
    } = rule
    else {
        return Ok(());
    };
    source.validate()?;
    ensure!(
        matches!(command.as_str(), "GET" | "DEL" | "LRANGE"),
        "API-triggered Redis traffic supports GET, single-key DEL and LRANGE"
    );
    ensure!(
        keys.is_empty()
            && key_patterns.is_empty()
            && key_prefix.is_empty()
            && key_suffix.is_empty()
            && fields.is_empty()
            && initial_load_timeout_ms.is_none(),
        "API-triggered Redis rules use key_templates without startup snapshots or legacy selectors"
    );
    ensure!(
        !key_templates.is_empty() && key_templates.len() <= 64,
        "API-triggered Redis requires 1..64 key_templates"
    );
    let (binding, _) = source.binding();
    for template in key_templates {
        let (prefix, suffix) = template_affixes(template, binding).ok_or_else(|| {
            anyhow::anyhow!("key_template requires one {{{binding}}} identity and nonempty affixes")
        })?;
        ensure!(
            template.len() <= 1024
                && !prefix.contains(['\r', '\n'])
                && !suffix.contains(['\r', '\n']),
            "key_template is too long or contains a newline"
        );
    }
    ensure!(
        key_templates
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == key_templates.len(),
        "duplicate API-triggered Redis key_template"
    );
    ensure!(
        if command == "LRANGE" {
            arguments.len() == 2
                && arguments
                    .iter()
                    .all(|s| s.parse::<i64>().is_ok_and(|n| n.to_string() == *s))
        } else {
            arguments.is_empty()
        },
        "LRANGE requires two canonical integer arguments; GET/DEL require none"
    );
    Ok(())
}

pub(crate) fn template_affixes<'a>(template: &'a str, binding: &str) -> Option<(&'a str, &'a str)> {
    let marker = format!("{{{binding}}}");
    let (prefix, suffix) = template.split_once(&marker)?;
    (!prefix.is_empty() && !prefix.contains(['{', '}']) && !suffix.contains(['{', '}']))
        .then_some((prefix, suffix))
}

pub(crate) fn redis_identity(
    rule: &BackgroundDependencyRuleConfig,
    port: u16,
    command: &str,
    args: &[Vec<u8>],
) -> Option<String> {
    let BackgroundDependencyRuleConfig::Redis {
        trigger_source: Some(source),
        ports,
        command: selected,
        key_templates,
        arguments,
        ..
    } = rule
    else {
        return None;
    };
    if !ports.contains(&port)
        || selected != &command.to_ascii_uppercase()
        || args.len() != arguments.len() + 1
        || !args
            .iter()
            .skip(1)
            .zip(arguments)
            .all(|(a, b)| a == b.as_bytes())
    {
        return None;
    }
    let key = std::str::from_utf8(args.first()?).ok()?;
    key_templates.iter().find_map(|template| {
        let (prefix, suffix) = template_affixes(template, source.binding().0)?;
        let identity = key.strip_prefix(prefix)?.strip_suffix(suffix)?;
        identity
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == identity)?;
        Some(identity.to_string())
    })
}

fn valid_pointer(pointer: &str) -> bool {
    pointer.starts_with('/')
        && pointer.len() <= 512
        && !pointer.contains('*')
        && pointer
            .split('~')
            .skip(1)
            .all(|s| s.starts_with(['0', '1']))
}

fn scalar(value: &Value) -> bool {
    value.is_boolean() || value.is_number() || value.as_str().is_some_and(|s| s.len() <= 1024)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Prevent API-origin and ordinary rules from silently owning the same wire shape.
pub(crate) fn overlap(
    left: &BackgroundDependencyRuleConfig,
    right: &BackgroundDependencyRuleConfig,
) -> Option<bool> {
    let (
        BackgroundDependencyRuleConfig::Redis {
            ports: lp,
            command: lc,
            ..
        },
        BackgroundDependencyRuleConfig::Redis {
            ports: rp,
            command: rc,
            ..
        },
    ) = (left, right)
    else {
        return None;
    };
    if left.trigger_source().is_none() && right.trigger_source().is_none() {
        return None;
    }
    if lc != rc || !lp.iter().any(|p| rp.contains(p)) {
        return Some(false);
    }
    fn shapes(rule: &BackgroundDependencyRuleConfig) -> Vec<(String, String)> {
        let BackgroundDependencyRuleConfig::Redis {
            trigger_source,
            key_templates,
            keys,
            key_patterns,
            key_prefix,
            key_suffix,
            ..
        } = rule
        else {
            return Vec::new();
        };
        if let Some(source) = trigger_source {
            return key_templates
                .iter()
                .filter_map(|t| template_affixes(t, source.binding().0))
                .map(|(a, b)| (a.into(), b.into()))
                .collect();
        }
        let mut result: Vec<_> = keys.iter().map(|k| (k.clone(), String::new())).collect();
        result.extend(
            key_patterns
                .iter()
                .map(|p| (p.prefix.clone(), p.suffix.clone())),
        );
        if result.is_empty() {
            result.push((key_prefix.clone(), key_suffix.clone()));
        }
        result
    }
    Some(shapes(left).iter().any(|(a, b)| {
        shapes(right).iter().any(|(c, d)| {
            (a.starts_with(c) || c.starts_with(a)) && (b.ends_with(d) || d.ends_with(b))
        })
    }))
}
