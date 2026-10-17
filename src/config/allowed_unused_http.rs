use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use hyper::http::uri::Authority;
use serde::Serialize;

use super::HttpGatewayConfig;
use super::edit::write_atomic;

const FIELD: &str = "allowed_unused_http_hosts";

#[derive(Debug, Clone)]
pub struct AllowedUnusedHttpHostFeedback {
    pub project_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllowedUnusedHttpHostReport {
    pub rules: PathBuf,
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
            read(&self.rules_path, "source traffic policy")? == self.original_rules,
            "source traffic policy changed after planning; rerun plan before applying"
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
    ensure!(
        !feedback.hosts.is_empty(),
        "at least one --host is required"
    );
    for host in &feedback.hosts {
        normalize_host(host)?;
    }
    anyhow::bail!(
        "unbounded unused HTTP hosts have no unified rule effect; use a Source-proven process-owned HTTP selector or narrow capture scope; sharing does not authorize unused work"
    )
}

pub(super) fn validate_config(config: &HttpGatewayConfig) -> Result<()> {
    let mut unique = BTreeSet::new();
    for host in &config.allowed_unused_http_hosts {
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
