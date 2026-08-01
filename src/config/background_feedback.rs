use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use hyper::http::{Method, Uri, uri::Authority};
use serde::{Deserialize, Serialize};

use super::background_dependencies::{
    self, BackgroundDependencyResponseRole, BackgroundDependencyRuleConfig,
};
use super::edit::write_atomic;
use super::rule_document::{find_managed_block, managed_block_diff, newline, parse_and_validate};

const BEGIN_MARKER: &str = "# BEGIN AI-MANAGED BACKGROUND DEPENDENCIES";
const END_MARKER: &str = "# END AI-MANAGED BACKGROUND DEPENDENCIES";
const TABLE_HEADER: &str = "[[recording.background_dependencies]]";

#[derive(Debug, Clone)]
pub struct BackgroundDependencyFeedback {
    pub config_path: PathBuf,
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
    pub config: PathBuf,
    pub replay_report: PathBuf,
    pub name: String,
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
    config_path: PathBuf,
    replay_report_path: PathBuf,
    original_config: String,
    original_replay_report: String,
    updated_config: String,
    report: BackgroundDependencyReport,
}

pub(super) struct RuleConfigPlan {
    pub(super) original: String,
    pub(super) updated: String,
    pub(super) changed: bool,
    pub(super) diff: String,
}

impl BackgroundDependencyPlan {
    pub fn report(&self) -> &BackgroundDependencyReport {
        &self.report
    }

    pub fn apply(self) -> Result<BackgroundDependencyReport> {
        let current_config = read_file(&self.config_path, "recorder config")?;
        ensure!(
            current_config == self.original_config,
            "recorder config changed after planning; rerun plan before applying"
        );
        let current_replay_report = read_file(&self.replay_report_path, "replay report")?;
        ensure!(
            current_replay_report == self.original_replay_report,
            "replay report changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.config_path, self.updated_config.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_background_dependency(
    feedback: BackgroundDependencyFeedback,
) -> Result<BackgroundDependencyPlan> {
    validate_single_line("background dependency rule name", &feedback.name, 128)?;

    let authority = canonical_authority(&feedback.authority)?;
    let method = canonical_method(&feedback.method)?;
    let path_prefix = canonical_path_prefix(&feedback.path_prefix)?;
    let requested = BackgroundDependencyRuleConfig::Http {
        name: feedback.name.clone(),
        authorities: vec![authority.clone()],
        methods: vec![method.clone()],
        path_prefixes: vec![path_prefix.clone()],
        response_role: BackgroundDependencyResponseRole::Independent,
        source_revision: feedback.source_revision.clone(),
        source_evidence: feedback.source_evidence.clone(),
    };
    background_dependencies::validate(std::slice::from_ref(&requested))?;

    let original_replay_report = read_file(&feedback.replay_report_path, "replay report")?;
    let evidence = parse_replay_evidence(
        &original_replay_report,
        &feedback.replay_report_path,
        &authority,
        &method,
        &path_prefix,
    )?;

    let config_plan = plan_rule_config(&feedback.config_path, requested)?;

    Ok(BackgroundDependencyPlan {
        config_path: feedback.config_path.clone(),
        replay_report_path: feedback.replay_report_path.clone(),
        original_config: config_plan.original,
        original_replay_report,
        updated_config: config_plan.updated,
        report: BackgroundDependencyReport {
            config: feedback.config_path,
            replay_report: feedback.replay_report_path,
            name: feedback.name,
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
    config_path: &Path,
    requested: BackgroundDependencyRuleConfig,
) -> Result<RuleConfigPlan> {
    ensure_regular_config(config_path)?;
    let original = read_file(config_path, "recorder config")?;
    let config = parse_and_validate(&original, config_path)?;
    let mut rules = config.recording.background_dependencies.clone();
    if let Some(existing) = rules
        .iter_mut()
        .find(|rule| rule.name() == requested.name())
    {
        ensure_same_selector(existing, &requested)?;
        *existing = requested;
    } else {
        rules.push(requested);
    }
    background_dependencies::validate(&rules)?;
    rules.sort_by(|left, right| left.name().cmp(right.name()));

    let whole_file = 0..original.len();
    let managed = find_managed_block(
        &original,
        &whole_file,
        BEGIN_MARKER,
        END_MARKER,
        "background dependencies",
    )?;
    let total_headers = table_header_count(&original);
    let block = match managed {
        Some(block) => {
            ensure!(
                total_headers == table_header_count(&original[block.clone()])
                    && total_headers == config.recording.background_dependencies.len(),
                "recording.background_dependencies must be owned exclusively by its AI-managed block"
            );
            block
        }
        None => {
            ensure!(
                total_headers == 0 && config.recording.background_dependencies.is_empty(),
                "existing recording.background_dependencies must be enclosed by its AI-managed block"
            );
            original.len()..original.len()
        }
    };
    let old_block = &original[block.clone()];
    let new_block = render_block(
        &rules,
        newline(&original),
        old_block.is_empty(),
        old_block.ends_with('\n'),
        &original,
    );
    let updated = replace_range(&original, &block, &new_block);
    parse_and_validate(&updated, config_path)
        .context("generated recorder config failed validation")?;
    let changed = updated != original;
    let diff = if changed {
        managed_block_diff(config_path, &original, block.start, old_block, &new_block)
    } else {
        String::new()
    };
    Ok(RuleConfigPlan {
        original,
        updated,
        changed,
        diff,
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
    let report: ReplayEvidenceReport = serde_json::from_str(raw)
        .with_context(|| format!("failed to parse replay report {}", path.display()))?;
    ensure!(
        report.finalized,
        "background dependency evidence requires a finalized replay report"
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

fn ensure_same_selector(
    existing: &BackgroundDependencyRuleConfig,
    requested: &BackgroundDependencyRuleConfig,
) -> Result<()> {
    let same = match (existing, requested) {
        (
            BackgroundDependencyRuleConfig::Http {
                authorities: existing_authorities,
                methods: existing_methods,
                path_prefixes: existing_paths,
                ..
            },
            BackgroundDependencyRuleConfig::Http {
                authorities: requested_authorities,
                methods: requested_methods,
                path_prefixes: requested_paths,
                ..
            },
        ) => {
            existing_authorities == requested_authorities
                && existing_methods == requested_methods
                && existing_paths == requested_paths
        }
        (
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity: existing_identity,
                command: existing_command,
                key_start: existing_start,
                key_end: existing_end,
                key_separator: existing_separator,
                key_suffix: existing_suffix,
                ..
            },
            BackgroundDependencyRuleConfig::Memcached {
                breeze_identity: requested_identity,
                command: requested_command,
                key_start: requested_start,
                key_end: requested_end,
                key_separator: requested_separator,
                key_suffix: requested_suffix,
                ..
            },
        ) => {
            existing_identity == requested_identity
                && existing_command == requested_command
                && existing_start == requested_start
                && existing_end == requested_end
                && existing_separator == requested_separator
                && existing_suffix == requested_suffix
        }
        (
            BackgroundDependencyRuleConfig::Redis {
                ports: existing_ports,
                command: existing_command,
                key_prefix: existing_prefix,
                key_suffix: existing_suffix,
                ..
            },
            BackgroundDependencyRuleConfig::Redis {
                ports: requested_ports,
                command: requested_command,
                key_prefix: requested_prefix,
                key_suffix: requested_suffix,
                ..
            },
        ) => {
            existing_ports
                .iter()
                .all(|port| requested_ports.contains(port))
                && existing_command == requested_command
                && existing_prefix == requested_prefix
                && existing_suffix == requested_suffix
        }
        (
            BackgroundDependencyRuleConfig::Motan {
                group: existing_group,
                interface_name: existing_interface,
                method_name: existing_method,
                ..
            },
            BackgroundDependencyRuleConfig::Motan {
                group: requested_group,
                interface_name: requested_interface,
                method_name: requested_method,
                ..
            },
        ) => {
            existing_group == requested_group
                && existing_interface == requested_interface
                && existing_method == requested_method
        }
        _ => false,
    };
    ensure!(
        same,
        "background dependency rule name {:?} already exists with a different selector; choose a new name instead of broadening it",
        existing.name()
    );
    Ok(())
}

fn render_block(
    rules: &[BackgroundDependencyRuleConfig],
    newline: &str,
    appending: bool,
    old_trailing_newline: bool,
    original: &str,
) -> String {
    let mut output = String::new();
    if appending && !original.is_empty() {
        if !original.ends_with(['\n', '\r']) {
            output.push_str(newline);
        }
        output.push_str(newline);
    }
    push_line(&mut output, BEGIN_MARKER, newline);
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            output.push_str(newline);
        }
        render_rule(&mut output, rule, newline);
    }
    output.push_str(END_MARKER);
    if appending || old_trailing_newline {
        output.push_str(newline);
    }
    output
}

fn render_rule(output: &mut String, rule: &BackgroundDependencyRuleConfig, newline: &str) {
    push_line(output, TABLE_HEADER, newline);
    match rule {
        BackgroundDependencyRuleConfig::Http {
            name,
            authorities,
            methods,
            path_prefixes,
            source_revision,
            source_evidence,
            ..
        } => {
            push_assignment(output, "name", name, newline);
            push_line(output, "protocol = \"http\"", newline);
            push_array(output, "authorities", authorities, newline);
            push_array(output, "methods", methods, newline);
            push_array(output, "path_prefixes", path_prefixes, newline);
            push_line(output, "response_role = \"independent\"", newline);
            push_assignment(output, "source_revision", source_revision, newline);
            push_assignment(output, "source_evidence", source_evidence, newline);
        }
        BackgroundDependencyRuleConfig::Memcached {
            name,
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
            push_assignment(output, "name", name, newline);
            push_line(output, "protocol = \"memcached\"", newline);
            push_assignment(output, "breeze_identity", breeze_identity, newline);
            push_assignment(output, "command", command, newline);
            push_line(output, &format!("key_start = {key_start}"), newline);
            push_line(output, &format!("key_end = {key_end}"), newline);
            push_assignment(output, "key_separator", key_separator, newline);
            push_assignment(output, "key_suffix", key_suffix, newline);
            push_line(
                output,
                &format!("initial_load_timeout_ms = {initial_load_timeout_ms}"),
                newline,
            );
            push_line(output, "response_role = \"runtime_state\"", newline);
            push_assignment(output, "source_revision", source_revision, newline);
            push_assignment(output, "source_evidence", source_evidence, newline);
        }
        BackgroundDependencyRuleConfig::Redis {
            name,
            ports,
            command,
            key_prefix,
            key_suffix,
            source_revision,
            source_evidence,
            ..
        } => {
            push_assignment(output, "name", name, newline);
            push_line(output, "protocol = \"redis\"", newline);
            push_u16_array(output, "ports", ports, newline);
            push_assignment(output, "command", command, newline);
            push_assignment(output, "key_prefix", key_prefix, newline);
            push_assignment(output, "key_suffix", key_suffix, newline);
            push_line(output, "response_role = \"independent\"", newline);
            push_assignment(output, "source_revision", source_revision, newline);
            push_assignment(output, "source_evidence", source_evidence, newline);
        }
        BackgroundDependencyRuleConfig::Motan {
            name,
            group,
            interface_name,
            method_name,
            source_revision,
            source_evidence,
        } => {
            push_assignment(output, "name", name, newline);
            push_line(output, "protocol = \"motan\"", newline);
            push_assignment(output, "group", group, newline);
            push_assignment(output, "interface_name", interface_name, newline);
            push_assignment(output, "method_name", method_name, newline);
            push_assignment(output, "source_revision", source_revision, newline);
            push_assignment(output, "source_evidence", source_evidence, newline);
        }
    }
}

fn push_array(output: &mut String, field: &str, values: &[String], newline: &str) {
    let values = values
        .iter()
        .map(|value| toml::Value::String(value.clone()).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    push_line(output, &format!("{field} = [{values}]"), newline);
}

fn push_u16_array(output: &mut String, field: &str, values: &[u16], newline: &str) {
    let values = values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    push_line(output, &format!("{field} = [{values}]"), newline);
}

fn push_assignment(output: &mut String, field: &str, value: &str, newline: &str) {
    let value = toml::Value::String(value.to_string());
    push_line(output, &format!("{field} = {value}"), newline);
}

fn push_line(output: &mut String, line: &str, newline: &str) {
    output.push_str(line);
    output.push_str(newline);
}

fn replace_range(original: &str, range: &Range<usize>, replacement: &str) -> String {
    let mut updated = String::with_capacity(original.len() + replacement.len());
    updated.push_str(&original[..range.start]);
    updated.push_str(replacement);
    updated.push_str(&original[range.end..]);
    updated
}

fn table_header_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| line.trim() == TABLE_HEADER)
        .count()
}

fn canonical_authority(value: &str) -> Result<String> {
    validate_single_line("background dependency authority", value, 512)?;
    ensure!(
        !value.contains('*'),
        "background dependency authority must be exact and cannot contain wildcards"
    );
    let authority = value
        .parse::<Authority>()
        .with_context(|| format!("invalid background dependency authority {value:?}"))?;
    let host = authority.host().to_ascii_lowercase();
    Ok(match authority.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn canonical_method(value: &str) -> Result<String> {
    validate_single_line("background dependency HTTP method", value, 64)?;
    let method = value
        .parse::<Method>()
        .with_context(|| format!("invalid background dependency HTTP method {value:?}"))?;
    Ok(method.as_str().to_ascii_uppercase())
}

fn canonical_path_prefix(value: &str) -> Result<String> {
    validate_single_line("background dependency path prefix", value, 2_048)?;
    ensure!(
        value.starts_with('/') && !value.contains(['?', '#']),
        "background dependency path prefix must start with '/' and contain no query or fragment"
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

fn ensure_regular_config(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect recorder config {}", path.display()))?;
    ensure!(metadata.is_file(), "recorder config must be a regular file");
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to replace a symlinked recorder config"
    );
    Ok(())
}

fn read_file(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
mod tests;
