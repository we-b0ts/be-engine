use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::background_dependencies::{
    self, BackgroundDependencyResponseRole, BackgroundDependencyRuleConfig,
    matches_memcached_key_series,
};
use super::background_feedback::{RuleConfigPlan, plan_rule_config};
use super::edit::write_atomic;
use crate::breeze;

#[derive(Debug, Clone)]
pub struct BreezeMemcachedBackgroundDependencyFeedback {
    pub config_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub name: String,
    pub breeze_resource: String,
    pub command: String,
    pub key_start: u64,
    pub key_end: u64,
    pub key_separator: String,
    pub key_suffix: String,
    pub initial_load_timeout_ms: u64,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreezeMemcachedBackgroundDependencyReport {
    pub config: PathBuf,
    pub replay_report: PathBuf,
    pub name: String,
    pub protocol: &'static str,
    pub response_role: &'static str,
    pub breeze_resource: String,
    pub breeze_identity: String,
    pub resolved_port: u16,
    pub command: String,
    pub key_start: u64,
    pub key_end: u64,
    pub key_separator: String,
    pub key_suffix: String,
    pub initial_load_timeout_ms: u64,
    pub source_revision: String,
    pub source_evidence: String,
    pub matched_unused_exchanges: usize,
    pub matched_case_ids: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct BreezeMemcachedBackgroundDependencyPlan {
    config_path: PathBuf,
    replay_report_path: PathBuf,
    original_config: String,
    original_replay_report: String,
    updated_config: String,
    dependency_evidence: Vec<EvidenceSnapshot>,
    socks_dir: PathBuf,
    report: BreezeMemcachedBackgroundDependencyReport,
}

impl BreezeMemcachedBackgroundDependencyPlan {
    pub fn report(&self) -> &BreezeMemcachedBackgroundDependencyReport {
        &self.report
    }

    pub fn apply(self) -> Result<BreezeMemcachedBackgroundDependencyReport> {
        ensure!(
            read_file(&self.config_path, "recorder config")? == self.original_config,
            "recorder config changed after planning; rerun plan before applying"
        );
        ensure!(
            read_file(&self.replay_report_path, "replay report")? == self.original_replay_report,
            "replay report changed after planning; rerun plan before applying"
        );
        for expected in &self.dependency_evidence {
            ensure!(
                snapshot_file(&expected.path, "dependency evidence")? == *expected,
                "case dependency evidence {} changed after planning; rerun plan before applying",
                expected.path.display()
            );
        }
        let descriptor = breeze::resolve_identity(&self.socks_dir, &self.report.breeze_identity)?;
        ensure!(
            descriptor.port == self.report.resolved_port,
            "Breeze descriptor port changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.config_path, self.updated_config.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_breeze_memcached_background_dependency(
    feedback: BreezeMemcachedBackgroundDependencyFeedback,
) -> Result<BreezeMemcachedBackgroundDependencyPlan> {
    plan_in(feedback, Path::new(breeze::SOCKS_DIR))
}

fn plan_in(
    feedback: BreezeMemcachedBackgroundDependencyFeedback,
    socks_dir: &Path,
) -> Result<BreezeMemcachedBackgroundDependencyPlan> {
    validate_single_line("background dependency rule name", &feedback.name, 128)?;
    validate_single_line(
        "background dependency Breeze business resource",
        &feedback.breeze_resource,
        512,
    )?;
    let command = feedback.command.to_ascii_lowercase();
    let descriptor = breeze::resolve_business_resource(socks_dir, &feedback.breeze_resource, "mc")?;
    let requested = BackgroundDependencyRuleConfig::Memcached {
        name: feedback.name.clone(),
        breeze_identity: descriptor.identity.clone(),
        command: command.clone(),
        key_start: feedback.key_start,
        key_end: feedback.key_end,
        key_separator: feedback.key_separator.clone(),
        key_suffix: feedback.key_suffix.clone(),
        initial_load_timeout_ms: feedback.initial_load_timeout_ms,
        response_role: BackgroundDependencyResponseRole::RuntimeState,
        source_revision: feedback.source_revision.clone(),
        source_evidence: feedback.source_evidence.clone(),
    };
    background_dependencies::validate(std::slice::from_ref(&requested))?;

    let original_replay_report = read_file(&feedback.replay_report_path, "replay report")?;
    let evidence = parse_replay_evidence(
        &original_replay_report,
        &feedback.replay_report_path,
        descriptor.port,
        feedback.key_start,
        feedback.key_end,
        feedback.key_separator.as_bytes()[0],
        feedback.key_suffix.as_bytes(),
    )?;
    let RuleConfigPlan {
        original,
        updated,
        changed,
        diff,
    } = plan_rule_config(&feedback.config_path, requested)?;

    Ok(BreezeMemcachedBackgroundDependencyPlan {
        config_path: feedback.config_path.clone(),
        replay_report_path: feedback.replay_report_path.clone(),
        original_config: original,
        original_replay_report,
        updated_config: updated,
        dependency_evidence: evidence.files,
        socks_dir: socks_dir.to_path_buf(),
        report: BreezeMemcachedBackgroundDependencyReport {
            config: feedback.config_path,
            replay_report: feedback.replay_report_path,
            name: feedback.name,
            protocol: "memcached",
            response_role: "runtime_state",
            breeze_resource: feedback.breeze_resource,
            breeze_identity: descriptor.identity,
            resolved_port: descriptor.port,
            command,
            key_start: feedback.key_start,
            key_end: feedback.key_end,
            key_separator: feedback.key_separator,
            key_suffix: feedback.key_suffix,
            initial_load_timeout_ms: feedback.initial_load_timeout_ms,
            source_revision: feedback.source_revision,
            source_evidence: feedback.source_evidence,
            matched_unused_exchanges: evidence.count,
            matched_case_ids: evidence.case_ids,
            changed,
            applied: false,
            diff,
        },
    })
}

#[derive(Debug, Deserialize)]
struct ReplayEvidenceReport {
    version: u8,
    finalized: bool,
    #[serde(default)]
    global_dependencies_path: Option<PathBuf>,
    #[serde(default)]
    cases: Vec<ReplayCaseEvidence>,
    #[serde(default)]
    memcached: CommandProtocolEvidence,
}

#[derive(Debug, Deserialize)]
struct ReplayCaseEvidence {
    case_id: String,
    dependencies_path: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct CommandProtocolEvidence {
    #[serde(default)]
    unsupported: Vec<CommandRequestEvidence>,
    #[serde(default)]
    unsafe_events: Vec<CommandRequestEvidence>,
    #[serde(default)]
    unused_case: Vec<CommandUnusedEvidence>,
    #[serde(default)]
    unused_global: Vec<CommandUnusedEvidence>,
}

#[derive(Debug, Deserialize)]
struct CommandRequestEvidence {
    target: CommandTargetEvidence,
    command: String,
}

#[derive(Debug, Deserialize)]
struct CommandUnusedEvidence {
    index: usize,
    case_id: Option<String>,
    target: CommandTargetEvidence,
    command: String,
}

#[derive(Debug, Deserialize)]
struct CommandTargetEvidence {
    port: u16,
}

struct EvidenceMatch {
    count: usize,
    case_ids: Vec<String>,
    files: Vec<EvidenceSnapshot>,
}

#[derive(Debug, Eq, PartialEq)]
struct EvidenceSnapshot {
    path: PathBuf,
    len: u64,
    fingerprint: u64,
}

fn parse_replay_evidence(
    raw: &str,
    report_path: &Path,
    port: u16,
    key_start: u64,
    key_end: u64,
    key_separator: u8,
    key_suffix: &[u8],
) -> Result<EvidenceMatch> {
    let report: ReplayEvidenceReport = serde_json::from_str(raw)
        .with_context(|| format!("failed to parse replay report {}", report_path.display()))?;
    ensure!(
        report.version == 6,
        "Memcached background dependency evidence requires replay report version 6"
    );
    ensure!(
        report.finalized,
        "background dependency evidence requires a finalized replay report"
    );
    ensure!(
        !report
            .memcached
            .unsupported
            .iter()
            .chain(&report.memcached.unsafe_events)
            .any(|event| event.target.port == port && event.command.eq_ignore_ascii_case("get")),
        "Memcached background selector shares its Breeze port and command with unsupported or unsafe target traffic"
    );
    let unused_case = report
        .memcached
        .unused_case
        .iter()
        .filter(|event| event.target.port == port && event.command.eq_ignore_ascii_case("get"))
        .map(|event| (event.index, event))
        .collect::<BTreeMap<_, _>>();
    let unused_global = report
        .memcached
        .unused_global
        .iter()
        .filter(|event| event.target.port == port && event.command.eq_ignore_ascii_case("get"))
        .map(|event| (event.index, event))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        !unused_case.is_empty() || !unused_global.is_empty(),
        "Memcached background selector matches no unused case or Global exchange on the resolved Breeze port"
    );

    let mut files = Vec::new();
    let mut exchange_index = 0;
    let mut count = 0_usize;
    let mut case_ids = BTreeSet::new();
    if let Some(recorded) = report.global_dependencies_path {
        let path = resolve_evidence_path(report_path, &recorded);
        let contents = read_file(&path, "Global dependency evidence")?;
        scan_memcached_dependency_file(
            &contents,
            &path,
            &unused_global,
            None,
            &mut exchange_index,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            &mut count,
            &mut case_ids,
        )?;
        files.push(snapshot_bytes(path, contents.as_bytes()));
    }
    for case in report.cases {
        let path = resolve_evidence_path(report_path, &case.dependencies_path);
        let contents = read_file(&path, "case dependency evidence")?;
        scan_memcached_dependency_file(
            &contents,
            &path,
            &unused_case,
            Some(&case.case_id),
            &mut exchange_index,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            &mut count,
            &mut case_ids,
        )?;
        files.push(snapshot_bytes(path, contents.as_bytes()));
    }
    ensure!(
        count > 0,
        "Memcached background selector matches no unused case or Global key in immutable dependency evidence"
    );
    Ok(EvidenceMatch {
        count,
        case_ids: case_ids.into_iter().collect(),
        files,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_memcached_dependency_file(
    contents: &str,
    path: &Path,
    unused: &BTreeMap<usize, &CommandUnusedEvidence>,
    expected_case_id: Option<&str>,
    exchange_index: &mut usize,
    key_start: u64,
    key_end: u64,
    key_separator: u8,
    key_suffix: &[u8],
    count: &mut usize,
    case_ids: &mut BTreeSet<String>,
) -> Result<()> {
    for (line_index, line) in contents.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!(
                "invalid dependency JSON at {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        if value.get("event_type").and_then(serde_json::Value::as_str) != Some("memcached_exchange")
        {
            continue;
        }
        let current_index = *exchange_index;
        *exchange_index += 1;
        let Some(recorded) = unused.get(&current_index) else {
            continue;
        };
        ensure!(
            recorded.case_id.as_deref() == expected_case_id,
            "replay report Memcached exchange index {current_index} does not match its immutable dependency evidence scope"
        );
        ensure!(
            value.get("target_port").and_then(serde_json::Value::as_u64)
                == Some(u64::from(recorded.target.port))
                && value
                    .get("command")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|command| command.eq_ignore_ascii_case(&recorded.command)),
            "replay report Memcached exchange index {current_index} does not match its recorded target or command"
        );
        let Some(key) = decode_key(&value)? else {
            continue;
        };
        if !matches_memcached_key_series(&key, key_start, key_end, key_separator, key_suffix) {
            continue;
        }
        ensure!(
            value
                .get("replay_safe")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            "Memcached background selector matches replay-unsafe evidence"
        );
        *count += 1;
        if let Some(case_id) = expected_case_id {
            case_ids.insert(case_id.to_string());
        }
    }
    Ok(())
}

fn snapshot_file(path: &Path, label: &str) -> Result<EvidenceSnapshot> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?
        .len();
    let mut fingerprint = FNV_OFFSET_BASIS;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        fingerprint = update_fingerprint(fingerprint, &buffer[..read]);
    }
    Ok(EvidenceSnapshot {
        path: path.to_path_buf(),
        len,
        fingerprint,
    })
}

fn snapshot_bytes(path: PathBuf, contents: &[u8]) -> EvidenceSnapshot {
    EvidenceSnapshot {
        path,
        len: contents.len() as u64,
        fingerprint: update_fingerprint(FNV_OFFSET_BASIS, contents),
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn update_fingerprint(mut fingerprint: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        fingerprint ^= u64::from(*byte);
        fingerprint = fingerprint.wrapping_mul(FNV_PRIME);
    }
    fingerprint
}

fn decode_key(value: &serde_json::Value) -> Result<Option<Vec<u8>>> {
    let Some(key) = value.get("key").and_then(|value| value.as_object()) else {
        return Ok(None);
    };
    ensure!(
        key.get("truncated").and_then(|value| value.as_bool()) == Some(false),
        "Memcached background selector cannot use a truncated recorded key"
    );
    let encoding = key
        .get("encoding")
        .and_then(|value| value.as_str())
        .context("recorded Memcached key is missing its encoding")?;
    let data = key
        .get("data")
        .and_then(|value| value.as_str())
        .context("recorded Memcached key is missing its data")?;
    match encoding {
        "utf8" => Ok(Some(data.as_bytes().to_vec())),
        "base64" => STANDARD
            .decode(data.as_bytes())
            .map(Some)
            .context("recorded Memcached key contains invalid base64"),
        other => anyhow::bail!("recorded Memcached key has unsupported encoding {other:?}"),
    }
}

fn resolve_evidence_path(report_path: &Path, recorded: &Path) -> PathBuf {
    if recorded.is_absolute() || recorded.is_file() {
        return recorded.to_path_buf();
    }
    report_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(recorded)
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

fn read_file(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
mod tests;
