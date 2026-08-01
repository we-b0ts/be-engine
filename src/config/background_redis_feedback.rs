use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::background_dependencies::{
    self, BackgroundDependencyResponseRole, BackgroundDependencyRuleConfig, matches_redis_key,
};
use super::background_feedback::{RuleConfigPlan, plan_rule_config};
use super::edit::write_atomic;

#[derive(Debug, Clone)]
pub struct RedisBackgroundDependencyFeedback {
    pub config_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub name: String,
    pub ports: Vec<u16>,
    pub command: String,
    pub key_prefix: String,
    pub key_suffix: String,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisBackgroundDependencyReport {
    pub config: PathBuf,
    pub replay_report: PathBuf,
    pub name: String,
    pub protocol: &'static str,
    pub response_role: &'static str,
    pub ports: Vec<u16>,
    pub command: String,
    pub key_prefix: String,
    pub key_suffix: String,
    pub source_revision: String,
    pub source_evidence: String,
    pub matched_unused_exchanges: usize,
    pub matched_case_ids: Vec<String>,
    pub observed_ports: Vec<u16>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct RedisBackgroundDependencyPlan {
    config_path: PathBuf,
    replay_report_path: PathBuf,
    original_config: String,
    original_replay_report: String,
    updated_config: String,
    dependency_evidence: Vec<EvidenceSnapshot>,
    report: RedisBackgroundDependencyReport,
}

impl RedisBackgroundDependencyPlan {
    pub fn report(&self) -> &RedisBackgroundDependencyReport {
        &self.report
    }

    pub fn apply(self) -> Result<RedisBackgroundDependencyReport> {
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
        if self.report.changed {
            write_atomic(&self.config_path, self.updated_config.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_redis_background_dependency(
    feedback: RedisBackgroundDependencyFeedback,
) -> Result<RedisBackgroundDependencyPlan> {
    let mut ports = feedback.ports;
    ports.sort_unstable();
    let command = feedback.command.to_ascii_uppercase();
    let requested = BackgroundDependencyRuleConfig::Redis {
        name: feedback.name.clone(),
        ports: ports.clone(),
        command: command.clone(),
        key_prefix: feedback.key_prefix.clone(),
        key_suffix: feedback.key_suffix.clone(),
        response_role: BackgroundDependencyResponseRole::Independent,
        source_revision: feedback.source_revision.clone(),
        source_evidence: feedback.source_evidence.clone(),
    };
    background_dependencies::validate(std::slice::from_ref(&requested))?;

    let original_replay_report = read_file(&feedback.replay_report_path, "replay report")?;
    let evidence = parse_replay_evidence(
        &original_replay_report,
        &feedback.replay_report_path,
        &ports,
        &command,
        feedback.key_prefix.as_bytes(),
        feedback.key_suffix.as_bytes(),
    )?;
    let RuleConfigPlan {
        original,
        updated,
        changed,
        diff,
    } = plan_rule_config(&feedback.config_path, requested)?;

    Ok(RedisBackgroundDependencyPlan {
        config_path: feedback.config_path.clone(),
        replay_report_path: feedback.replay_report_path.clone(),
        original_config: original,
        original_replay_report,
        updated_config: updated,
        dependency_evidence: evidence.files,
        report: RedisBackgroundDependencyReport {
            config: feedback.config_path,
            replay_report: feedback.replay_report_path,
            name: feedback.name,
            protocol: "redis",
            response_role: "independent",
            ports,
            command,
            key_prefix: feedback.key_prefix,
            key_suffix: feedback.key_suffix,
            source_revision: feedback.source_revision,
            source_evidence: feedback.source_evidence,
            matched_unused_exchanges: evidence.count,
            matched_case_ids: evidence.case_ids,
            observed_ports: evidence.observed_ports,
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
    redis: CommandProtocolEvidence,
}

#[derive(Debug, Deserialize)]
struct ReplayCaseEvidence {
    case_id: String,
    dependencies_path: PathBuf,
}

#[derive(Debug, Default, Deserialize)]
struct CommandProtocolEvidence {
    #[serde(default)]
    unmatched: Vec<CommandRequestEvidence>,
    #[serde(default)]
    unsupported: Vec<CommandRequestEvidence>,
    #[serde(default)]
    unsafe_events: Vec<CommandRequestEvidence>,
    #[serde(default)]
    unused_case: Vec<CommandUnusedEvidence>,
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
    observed_ports: Vec<u16>,
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
    ports: &[u16],
    command: &str,
    key_prefix: &[u8],
    key_suffix: &[u8],
) -> Result<EvidenceMatch> {
    let report: ReplayEvidenceReport = serde_json::from_str(raw)
        .with_context(|| format!("failed to parse replay report {}", report_path.display()))?;
    ensure!(
        report.version == 6,
        "Redis background dependency evidence requires replay report version 6"
    );
    ensure!(
        report.finalized,
        "background dependency evidence requires a finalized replay report"
    );
    ensure!(
        !report
            .redis
            .unmatched
            .iter()
            .chain(&report.redis.unsupported)
            .chain(&report.redis.unsafe_events)
            .any(|event| ports.contains(&event.target.port)
                && event.command.eq_ignore_ascii_case(command)),
        "Redis background selector shares a configured port and command with unmatched, unsupported, or unsafe target traffic"
    );
    let unused = report
        .redis
        .unused_case
        .iter()
        .filter(|event| {
            ports.contains(&event.target.port) && event.command.eq_ignore_ascii_case(command)
        })
        .map(|event| (event.index, event))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        !unused.is_empty(),
        "Redis background selector matches no unused case exchange on the configured ports"
    );

    let mut files = Vec::new();
    let mut exchange_index = if let Some(recorded) = report.global_dependencies_path {
        let path = resolve_evidence_path(report_path, &recorded);
        let count = redis_exchange_count(&path)?;
        files.push(snapshot_file(&path, "Global dependency evidence")?);
        count
    } else {
        0
    };
    let mut count = 0;
    let mut case_ids = BTreeSet::new();
    let mut observed_ports = BTreeSet::new();
    for case in report.cases {
        let path = resolve_evidence_path(report_path, &case.dependencies_path);
        let contents = read_file(&path, "case dependency evidence")?;
        for (line_index, line) in contents.lines().enumerate() {
            let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
                format!(
                    "invalid dependency JSON at {} line {}",
                    path.display(),
                    line_index + 1
                )
            })?;
            if value.get("event_type").and_then(serde_json::Value::as_str) != Some("redis_exchange")
            {
                continue;
            }
            let current_index = exchange_index;
            exchange_index += 1;
            let Some(recorded) = unused.get(&current_index) else {
                continue;
            };
            ensure!(
                recorded.case_id.as_deref() == Some(case.case_id.as_str()),
                "replay report Redis exchange index {current_index} does not match its case dependency evidence"
            );
            ensure!(
                value.get("target_port").and_then(serde_json::Value::as_u64)
                    == Some(u64::from(recorded.target.port))
                    && value
                        .get("command")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| value.eq_ignore_ascii_case(&recorded.command)),
                "replay report Redis exchange index {current_index} does not match its recorded target or command"
            );
            let Some(key) = decode_first_arg(&value)? else {
                continue;
            };
            if matches_redis_key(&key, key_prefix, key_suffix) {
                ensure!(
                    value
                        .get("replay_safe")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true),
                    "Redis background selector matches replay-unsafe evidence"
                );
                count += 1;
                case_ids.insert(case.case_id.clone());
                observed_ports.insert(recorded.target.port);
            }
        }
        files.push(snapshot_bytes(path, contents.as_bytes()));
    }
    ensure!(
        count > 0,
        "Redis background selector matches no unused case key in immutable dependency evidence"
    );
    Ok(EvidenceMatch {
        count,
        case_ids: case_ids.into_iter().collect(),
        observed_ports: observed_ports.into_iter().collect(),
        files,
    })
}

fn redis_exchange_count(path: &Path) -> Result<usize> {
    let file = fs::File::open(path).with_context(|| {
        format!(
            "failed to read Global dependency evidence {}",
            path.display()
        )
    })?;
    let mut count = 0;
    for (line_index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| {
            format!(
                "failed to read Global dependency evidence {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        let value: serde_json::Value = serde_json::from_str(&line).with_context(|| {
            format!(
                "invalid dependency JSON at {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        count += usize::from(
            value.get("event_type").and_then(serde_json::Value::as_str) == Some("redis_exchange"),
        );
    }
    Ok(count)
}

fn decode_first_arg(value: &serde_json::Value) -> Result<Option<Vec<u8>>> {
    let Some(arg) = value
        .get("args")
        .and_then(serde_json::Value::as_array)
        .and_then(|args| args.first())
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    ensure!(
        arg.get("truncated").and_then(serde_json::Value::as_bool) == Some(false),
        "Redis background selector cannot use a truncated recorded key"
    );
    let encoding = arg
        .get("encoding")
        .and_then(serde_json::Value::as_str)
        .context("recorded Redis key is missing its encoding")?;
    let data = arg
        .get("data")
        .and_then(serde_json::Value::as_str)
        .context("recorded Redis key is missing its data")?;
    match encoding {
        "utf8" => Ok(Some(data.as_bytes().to_vec())),
        "base64" => STANDARD
            .decode(data.as_bytes())
            .map(Some)
            .context("recorded Redis key contains invalid base64"),
        other => anyhow::bail!("recorded Redis key has unsupported encoding {other:?}"),
    }
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

fn resolve_evidence_path(report_path: &Path, recorded: &Path) -> PathBuf {
    if recorded.is_absolute() || recorded.is_file() {
        return recorded.to_path_buf();
    }
    report_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(recorded)
}

fn read_file(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
#[path = "background_redis_feedback/tests.rs"]
mod tests;
