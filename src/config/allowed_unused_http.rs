use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use hyper::http::uri::Authority;
use serde::Serialize;

use super::edit::write_atomic;
use super::rule_document::whole_file_diff;
use super::{
    AppConfig, CoordinatorHttpRuleConfig, CoordinatorRulesConfig, HttpGatewayConfig,
    HttpGatewayRuleConfig,
};

const FIELD: &str = "allowed_unused_http_hosts";

#[derive(Debug, Clone)]
pub struct AllowedUnusedHttpHostFeedback {
    pub project_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub rule_name: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllowedUnusedHttpHostReport {
    pub rules: PathBuf,
    pub rule: String,
    pub changed: bool,
    pub applied: bool,
    pub hosts_before: Vec<String>,
    pub hosts_after: Vec<String>,
    pub added: Vec<String>,
    pub diff: String,
}

#[derive(Debug)]
pub struct AllowedUnusedHttpHostPlan {
    project_config_path: PathBuf,
    rules_path: PathBuf,
    original_project_config: String,
    original_rules: String,
    updated_rules: String,
    report: AllowedUnusedHttpHostReport,
}

impl AllowedUnusedHttpHostPlan {
    pub fn report(&self) -> &AllowedUnusedHttpHostReport {
        &self.report
    }

    pub fn apply(self) -> Result<AllowedUnusedHttpHostReport> {
        ensure!(
            read(&self.project_config_path, "project config")? == self.original_project_config,
            "project config changed after planning; rerun plan before applying"
        );
        ensure!(
            read(&self.rules_path, "coordinator rules")? == self.original_rules,
            "coordinator rules changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_allowed_unused_http_hosts(
    feedback: AllowedUnusedHttpHostFeedback,
) -> Result<AllowedUnusedHttpHostPlan> {
    validate_single_line("rule name", &feedback.rule_name)?;
    ensure!(
        !feedback.hosts.is_empty(),
        "at least one --host is required"
    );
    let requested = feedback
        .hosts
        .iter()
        .map(|host| normalize_host(host))
        .collect::<Result<BTreeSet<_>>>()?;
    let original_project_config = read(&feedback.project_config_path, "project config")?;
    let original_rules = read(&feedback.rules_path, "coordinator rules")?;
    let mut rules = CoordinatorRulesConfig::parse(&original_rules, &feedback.rules_path)?;
    let mut static_config = AppConfig::load_static(&feedback.project_config_path)?;
    named_rule(&static_config, &feedback.rule_name)?;
    let overlay = http_overlay_mut(&mut rules, &feedback.rule_name);
    let before = overlay
        .allowed_unused_http_hosts
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let after = before.union(&requested).cloned().collect::<BTreeSet<_>>();
    overlay.allowed_unused_http_hosts = after.iter().cloned().collect();
    rules.apply_to(&mut static_config)?;
    static_config.validate()?;
    let updated_rules = rules.render()?;
    let changed = updated_rules != original_rules;
    let added = after.difference(&before).cloned().collect::<Vec<_>>();
    let diff = if changed {
        whole_file_diff(&feedback.rules_path, &original_rules, &updated_rules)
    } else {
        String::new()
    };
    Ok(AllowedUnusedHttpHostPlan {
        project_config_path: feedback.project_config_path,
        rules_path: feedback.rules_path.clone(),
        original_project_config,
        original_rules,
        updated_rules,
        report: AllowedUnusedHttpHostReport {
            rules: feedback.rules_path,
            rule: feedback.rule_name,
            changed,
            applied: false,
            hosts_before: before.into_iter().collect(),
            hosts_after: after.into_iter().collect(),
            added,
            diff,
        },
    })
}

pub(super) fn validate_config(config: &HttpGatewayConfig) -> Result<()> {
    for rule in &config.exclude_rules {
        ensure!(
            rule.allowed_unused_http_hosts.is_empty(),
            "http_gateway.exclude_rules cannot define {FIELD}"
        );
    }
    for rule in &config.rules {
        validate_rule(rule)?;
    }
    Ok(())
}

fn named_rule<'a>(config: &'a AppConfig, name: &str) -> Result<&'a HttpGatewayRuleConfig> {
    let matches = config
        .http_gateway
        .rules
        .iter()
        .filter(|rule| rule.name.as_deref() == Some(name))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "expected exactly one recorder HTTP rule named {name:?}, found {}",
        matches.len()
    );
    Ok(matches[0])
}

fn http_overlay_mut<'a>(
    rules: &'a mut CoordinatorRulesConfig,
    name: &str,
) -> &'a mut CoordinatorHttpRuleConfig {
    if let Some(index) = rules.http.iter().position(|rule| rule.name == name) {
        return &mut rules.http[index];
    }
    rules.http.push(CoordinatorHttpRuleConfig {
        name: name.to_string(),
        source_revision: String::new(),
        case_path_patterns: Vec::new(),
        allowed_unused_http_hosts: Vec::new(),
    });
    rules
        .http
        .last_mut()
        .expect("just inserted coordinator rule")
}

fn validate_rule(rule: &HttpGatewayRuleConfig) -> Result<()> {
    if !rule.allowed_unused_http_hosts.is_empty() {
        ensure!(
            rule.name
                .as_ref()
                .is_some_and(|name| !name.trim().is_empty()),
            "{FIELD} requires a named recorder HTTP rule"
        );
    }
    let mut unique = BTreeSet::new();
    for host in &rule.allowed_unused_http_hosts {
        let normalized = normalize_host(host)?;
        ensure!(
            unique.insert(normalized),
            "duplicate {FIELD} entry {host:?}"
        );
    }
    Ok(())
}

fn normalize_host(value: &str) -> Result<String> {
    validate_single_line("allowed unused HTTP host", value)?;
    ensure!(
        value == value.trim(),
        "allowed unused HTTP host must not contain surrounding whitespace"
    );
    ensure!(
        !value.contains('*'),
        "allowed unused HTTP host must be exact and cannot contain wildcards: {value:?}"
    );
    let authority = value
        .parse::<Authority>()
        .with_context(|| format!("invalid allowed unused HTTP host {value:?}"))?;
    ensure!(
        authority.port_u16().is_none(),
        "allowed unused HTTP host must not include a port: {value:?}"
    );
    let normalized = authority.host().trim_end_matches('.').to_ascii_lowercase();
    ensure!(
        normalized == value,
        "allowed unused HTTP host must use canonical lowercase form without a trailing dot: {value:?}"
    );
    Ok(normalized)
}

fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    ensure!(
        !value.contains(['\r', '\n']),
        "{label} must fit on one line"
    );
    Ok(())
}

fn read(path: &std::path::Path, label: &str) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
mod tests;
