use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use hyper::http::{Method, Uri, uri::Authority};
use serde::{Deserialize, Serialize};

use super::SourceTrafficPolicyConfig;
use super::edit::write_atomic;
use super::process_owned_dependencies::{self, BackgroundDependencyRuleConfig};
use super::rule_document::whole_file_diff;

mod selector;

#[derive(Debug, Clone)]
pub struct BackgroundDependencyFeedback {
    pub rules_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub name: String,
    pub authority: String,
    pub method: String,
    pub path_prefix: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackgroundDependencyReport {
    pub rules: PathBuf,
    pub replay_report: PathBuf,
    pub name: String,
    pub effective_name: String,
    pub reused_existing: bool,
    pub protocol: &'static str,
    pub authority: String,
    pub method: String,
    pub path_prefix: String,
    pub source_revision: String,
    pub source_evidence: String,
    pub matched_unused_exchanges: usize,
    pub matched_case_ids: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct BackgroundDependencyPlan {
    rules_path: PathBuf,
    replay_report_path: PathBuf,
    original_rules: String,
    original_replay_report: String,
    updated_rules: String,
    report: BackgroundDependencyReport,
}

pub(super) struct RuleConfigPlan {
    pub(super) original: String,
    pub(super) updated: String,
    pub(super) changed: bool,
    pub(super) diff: String,
    pub(super) effective_name: String,
    pub(super) reused_existing: bool,
}

impl BackgroundDependencyPlan {
    pub fn report(&self) -> &BackgroundDependencyReport {
        &self.report
    }

    pub fn apply(self) -> Result<BackgroundDependencyReport> {
        let current_rules = read_file(&self.rules_path, "process-owned rules")?;
        ensure!(
            current_rules == self.original_rules,
            "process-owned rules changed after planning; rerun plan before applying"
        );
        let current_replay_report = read_file(&self.replay_report_path, "replay report")?;
        ensure!(
            current_replay_report == self.original_replay_report,
            "replay report changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_background_dependency(
    feedback: BackgroundDependencyFeedback,
) -> Result<BackgroundDependencyPlan> {
    validate_single_line("process-owned dependency rule name", &feedback.name, 128)?;

    let authority = canonical_authority(&feedback.authority)?;
    let method = canonical_method(&feedback.method)?;
    let path_prefix = canonical_path_prefix(&feedback.path_prefix)?;
    let requested = BackgroundDependencyRuleConfig::Http {
        name: feedback.name.clone(),
        authorities: vec![authority.clone()],
        methods: vec![method.clone()],
        path_prefixes: vec![path_prefix.clone()],
        source_revision: String::new(),
        source_evidence: feedback.source_evidence.clone(),
    };
    process_owned_dependencies::validate(std::slice::from_ref(&requested))?;

    let original_replay_report = read_file(&feedback.replay_report_path, "replay report")?;
    let evidence = parse_replay_evidence(
        &original_replay_report,
        &feedback.replay_report_path,
        &authority,
        &method,
        &path_prefix,
    )?;

    let config_plan = plan_rule_config(&feedback.rules_path, requested)?;

    Ok(BackgroundDependencyPlan {
        rules_path: feedback.rules_path.clone(),
        replay_report_path: feedback.replay_report_path.clone(),
        original_rules: config_plan.original,
        original_replay_report,
        updated_rules: config_plan.updated,
        report: BackgroundDependencyReport {
            rules: feedback.rules_path,
            replay_report: feedback.replay_report_path,
            name: feedback.name,
            effective_name: config_plan.effective_name,
            reused_existing: config_plan.reused_existing,
            protocol: "http",
            authority,
            method,
            path_prefix,
            source_revision: feedback.source_revision,
            source_evidence: feedback.source_evidence,
            matched_unused_exchanges: evidence.count,
            matched_case_ids: evidence.case_ids,
            changed: config_plan.changed,
            applied: false,
            diff: config_plan.diff,
        },
    })
}

pub(super) fn plan_rule_config(
    rules_path: &Path,
    requested: BackgroundDependencyRuleConfig,
) -> Result<RuleConfigPlan> {
    ensure_regular_rules_file(rules_path)?;
    let original = read_file(rules_path, "process-owned rules")?;
    let mut config = SourceTrafficPolicyConfig::parse(&original, rules_path)?;
    let mut rules = std::mem::take(&mut config.process_owned_dependencies);
    let requested_name = requested.name().to_string();
    let reused = rules
        .iter()
        .find(|rule| selector::covers(rule, &requested))
        .map(|rule| rule.name().to_string());
    let mut merged = None;
    if reused.is_none() {
        merged = selector::merge_compatible_redis_key_selector_rule(&mut rules, &requested)?;
        if merged.is_none()
            && let Some(existing) = rules
                .iter_mut()
                .find(|rule| rule.name() == requested.name())
        {
            selector::ensure_same(existing, &requested)?;
            *existing = requested;
        } else if merged.is_none() {
            rules.push(requested);
        }
    }
    let effective_name = if let Some(name) = reused.as_ref() {
        name.clone()
    } else if let Some(name) = merged {
        name
    } else {
        requested_name
    };
    process_owned_dependencies::validate(&rules)?;
    rules.sort_by(|left, right| left.name().cmp(right.name()));

    if reused.is_some() {
        return Ok(RuleConfigPlan {
            original: original.clone(),
            updated: original,
            changed: false,
            diff: String::new(),
            effective_name,
            reused_existing: true,
        });
    }
    config.process_owned_dependencies = rules;
    let updated = config
        .render()
        .context("generated process-owned rules failed validation")?;
    let changed = updated != original;
    let diff = if changed {
        whole_file_diff(rules_path, &original, &updated)
    } else {
        String::new()
    };
    Ok(RuleConfigPlan {
        original,
        updated,
        changed,
        diff,
        effective_name,
        reused_existing: false,
    })
}

#[derive(Debug, Deserialize)]
struct ReplayEvidenceReport {
    finalized: bool,
    #[serde(default)]
    unused_case_http_exchanges: Vec<HttpEvidence>,
    #[serde(default)]
    unmatched_http_requests: Vec<HttpEvidence>,
    #[serde(default)]
    unsupported_http_exchanges: Vec<HttpEvidence>,
    #[serde(default)]
    http_request_header_mismatches: Vec<HttpEvidence>,
}

#[derive(Debug, Deserialize)]
struct HttpEvidence {
    case_id: Option<String>,
    target: HttpEvidenceTarget,
    method: String,
    uri: String,
}

#[derive(Debug, Deserialize)]
struct HttpEvidenceTarget {
    host: String,
    port: u16,
}

struct EvidenceMatch {
    count: usize,
    case_ids: Vec<String>,
}

fn parse_replay_evidence(
    raw: &str,
    path: &Path,
    authority: &str,
    method: &str,
    path_prefix: &str,
) -> Result<EvidenceMatch> {
    let report: ReplayEvidenceReport =
        crate::replay::report::parse_background_dependency_evidence(raw)
            .with_context(|| format!("failed to parse replay report {}", path.display()))?;
    ensure!(
        report.finalized,
        "process-owned dependency evidence requires a finalized replay report"
    );
    let selector = HttpSelector::new(authority, method, path_prefix)?;
    ensure!(
        !report
            .unmatched_http_requests
            .iter()
            .any(|event| selector.matches(event)),
        "background selector also matches an unmatched target HTTP request"
    );
    ensure!(
        !report
            .unsupported_http_exchanges
            .iter()
            .any(|event| selector.matches(event)),
        "background selector also matches an unsupported target HTTP request"
    );
    ensure!(
        !report
            .http_request_header_mismatches
            .iter()
            .any(|event| selector.matches(event)),
        "background selector also matches a target HTTP request-header mismatch"
    );
    let matching = report
        .unused_case_http_exchanges
        .iter()
        .filter(|event| selector.matches(event))
        .collect::<Vec<_>>();
    ensure!(
        !matching.is_empty(),
        "background selector matches no unused case HTTP exchange in the replay report"
    );
    let case_ids = matching
        .iter()
        .filter_map(|event| event.case_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(EvidenceMatch {
        count: matching.len(),
        case_ids,
    })
}

struct HttpSelector {
    host: String,
    port: Option<u16>,
    method: String,
    path_prefix: String,
}

impl HttpSelector {
    fn new(authority: &str, method: &str, path_prefix: &str) -> Result<Self> {
        let authority = authority
            .parse::<Authority>()
            .context("validated background authority became invalid")?;
        Ok(Self {
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16(),
            method: method.to_string(),
            path_prefix: path_prefix.to_string(),
        })
    }

    fn matches(&self, evidence: &HttpEvidence) -> bool {
        evidence.target.host.eq_ignore_ascii_case(&self.host)
            && self.port.is_none_or(|port| port == evidence.target.port)
            && evidence.method.eq_ignore_ascii_case(&self.method)
            && uri_path(&evidence.uri).starts_with(&self.path_prefix)
    }
}

fn canonical_authority(value: &str) -> Result<String> {
    validate_single_line("process-owned dependency authority", value, 512)?;
    ensure!(
        !value.contains('*'),
        "process-owned dependency authority must be exact and cannot contain wildcards"
    );
    let authority = value
        .parse::<Authority>()
        .with_context(|| format!("invalid process-owned dependency authority {value:?}"))?;
    let host = authority.host().to_ascii_lowercase();
    Ok(match authority.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn canonical_method(value: &str) -> Result<String> {
    validate_single_line("process-owned dependency HTTP method", value, 64)?;
    let method = value
        .parse::<Method>()
        .with_context(|| format!("invalid process-owned dependency HTTP method {value:?}"))?;
    Ok(method.as_str().to_ascii_uppercase())
}

fn canonical_path_prefix(value: &str) -> Result<String> {
    validate_single_line("process-owned dependency path prefix", value, 2_048)?;
    ensure!(
        value.starts_with('/') && !value.contains(['?', '#']),
        "process-owned dependency path prefix must start with '/' and contain no query or fragment"
    );
    Ok(value.to_string())
}

fn uri_path(value: &str) -> String {
    value
        .parse::<Uri>()
        .ok()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| value.split('?').next().unwrap_or(value).to_string())
}

fn validate_single_line(label: &str, value: &str, max_len: usize) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    ensure!(
        value == value.trim() && !value.contains(['\r', '\n']),
        "{label} must be a single line without surrounding whitespace"
    );
    ensure!(
        value.len() <= max_len,
        "{label} must not exceed {max_len} bytes"
    );
    Ok(())
}

fn ensure_regular_rules_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect process-owned rules {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "process-owned rules must be a regular file"
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to replace symlinked process-owned rules"
    );
    Ok(())
}

fn read_file(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
mod tests;
