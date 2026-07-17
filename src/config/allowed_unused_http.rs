use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use hyper::http::uri::Authority;
use serde::Serialize;

use super::edit::write_atomic;
use super::rule_document::{
    assignment_count, find_managed_block, find_rule, insertion_before_assignment,
    managed_block_diff, newline, parse_and_validate, rule_range,
};
use super::{HttpGatewayConfig, HttpGatewayRuleConfig};

const BEGIN_MARKER: &str = "# BEGIN AI-MANAGED ALLOWED UNUSED HTTP HOSTS";
const END_MARKER: &str = "# END AI-MANAGED ALLOWED UNUSED HTTP HOSTS";
const FIELD: &str = "allowed_unused_http_hosts";

#[derive(Debug, Clone)]
pub struct AllowedUnusedHttpHostFeedback {
    pub config_path: PathBuf,
    pub rule_name: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllowedUnusedHttpHostReport {
    pub config: PathBuf,
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
    config_path: PathBuf,
    original: String,
    updated: String,
    report: AllowedUnusedHttpHostReport,
}

impl AllowedUnusedHttpHostPlan {
    pub fn report(&self) -> &AllowedUnusedHttpHostReport {
        &self.report
    }

    pub fn apply(self) -> Result<AllowedUnusedHttpHostReport> {
        let current = fs::read_to_string(&self.config_path).with_context(|| {
            format!(
                "failed to reread recorder config {}",
                self.config_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "recorder config changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.config_path, self.updated.as_bytes())?;
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

    let metadata = fs::symlink_metadata(&feedback.config_path).with_context(|| {
        format!(
            "failed to inspect recorder config {}",
            feedback.config_path.display()
        )
    })?;
    ensure!(metadata.is_file(), "recorder config must be a regular file");
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to replace a symlinked recorder config"
    );
    let original = fs::read_to_string(&feedback.config_path).with_context(|| {
        format!(
            "failed to read recorder config {}",
            feedback.config_path.display()
        )
    })?;
    let config = parse_and_validate(&original, &feedback.config_path)?;
    let (rule_index, rule) = find_rule(&config, &feedback.rule_name)?;
    let rule_range = rule_range(&original, rule_index, config.http_gateway.rules.len())?;
    let managed = find_managed_block(&original, &rule_range, BEGIN_MARKER, END_MARKER, FIELD)?;
    let rule_source = &original[rule_range.clone()];
    let total_assignments = assignment_count(rule_source, FIELD);
    let block = match managed {
        Some(block) => {
            ensure!(
                total_assignments == 1 && assignment_count(&original[block.clone()], FIELD) == 1,
                "{FIELD} must be owned exclusively by its AI-managed block"
            );
            block
        }
        None => {
            ensure!(
                total_assignments == 0,
                "existing {FIELD} must be enclosed by its AI-managed block"
            );
            let insertion = insertion_before_assignment(&original, &rule_range, "headers")
                .unwrap_or(rule_range.end);
            insertion..insertion
        }
    };

    let before = rule
        .allowed_unused_http_hosts
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let after = before.union(&requested).cloned().collect::<BTreeSet<_>>();
    let added = after.difference(&before).cloned().collect::<Vec<_>>();
    let old_block = &original[block.clone()];
    let new_block = render_managed_block(
        &after,
        newline(&original),
        old_block.is_empty() || old_block.ends_with('\n'),
    );
    let mut updated = String::with_capacity(original.len() + new_block.len());
    updated.push_str(&original[..block.start]);
    if old_block.is_empty() && block.start > 0 && !original[..block.start].ends_with(['\n', '\r']) {
        updated.push_str(newline(&original));
    }
    updated.push_str(&new_block);
    updated.push_str(&original[block.end..]);
    parse_and_validate(&updated, &feedback.config_path)
        .context("generated recorder config failed validation")?;

    let changed = updated != original;
    let diff = if changed {
        managed_block_diff(
            &feedback.config_path,
            &original,
            block.start,
            old_block,
            &new_block,
        )
    } else {
        String::new()
    };
    Ok(AllowedUnusedHttpHostPlan {
        config_path: feedback.config_path.clone(),
        original,
        updated,
        report: AllowedUnusedHttpHostReport {
            config: feedback.config_path,
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

fn validate_rule(rule: &HttpGatewayRuleConfig) -> Result<()> {
    if !rule.allowed_unused_http_hosts.is_empty() {
        ensure!(
            rule.name
                .as_ref()
                .is_some_and(|name| !name.trim().is_empty()),
            "{FIELD} requires a named [[http_gateway.rules]] entry"
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

fn render_managed_block(hosts: &BTreeSet<String>, newline: &str, trailing_newline: bool) -> String {
    let mut output = String::new();
    writeln_with(&mut output, BEGIN_MARKER, newline);
    writeln_with(&mut output, &format!("{FIELD} = ["), newline);
    for host in hosts {
        let quoted = toml::Value::String(host.clone()).to_string();
        writeln_with(&mut output, &format!("  {quoted},"), newline);
    }
    writeln_with(&mut output, "]", newline);
    output.push_str(END_MARKER);
    if trailing_newline {
        output.push_str(newline);
    }
    output
}

fn writeln_with(output: &mut String, line: &str, newline: &str) {
    output.push_str(line);
    output.push_str(newline);
}

#[cfg(test)]
mod tests;
