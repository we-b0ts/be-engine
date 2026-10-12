use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::background_feedback::{RuleConfigPlan, plan_rule_config};
use super::edit::write_atomic;
use super::process_owned_dependencies::{
    self, BackgroundDependencyRuleConfig, RedisKeyPatternConfig, matches_exact_redis_key,
    matches_redis_numeric_key_pattern, redis_rule_matches,
};

#[derive(Debug, Clone)]
pub struct RedisBackgroundDependencyFeedback {
    pub rules_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub name: String,
    pub ports: Vec<u16>,
    pub command: String,
    pub keys: Vec<String>,
    pub key_patterns: Vec<RedisKeyPatternConfig>,
    pub key_prefix: String,
    pub key_suffix: String,
    pub initial_load_timeout_ms: Option<u64>,
    pub fields: Vec<String>,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisBackgroundDependencyReport {
    pub rules: PathBuf,
    pub replay_report: PathBuf,
    pub name: String,
    pub effective_name: String,
    pub reused_existing: bool,
    pub protocol: &'static str,
    pub ports: Vec<u16>,
    pub command: String,
    pub keys: Vec<String>,
    pub key_patterns: Vec<RedisKeyPatternConfig>,
    pub key_prefix: String,
    pub key_suffix: String,
    pub initial_load_timeout_ms: Option<u64>,
    pub fields: Vec<String>,
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
    rules_path: PathBuf,
    replay_report_path: PathBuf,
    original_rules: String,
    original_replay_report: String,
    updated_rules: String,
    dependency_evidence: Vec<EvidenceSnapshot>,
    report: RedisBackgroundDependencyReport,
}

impl RedisBackgroundDependencyPlan {
    pub fn report(&self) -> &RedisBackgroundDependencyReport {
        &self.report
    }

    pub fn apply(self) -> Result<RedisBackgroundDependencyReport> {
        ensure!(
            read_file(&self.rules_path, "process-owned rules")? == self.original_rules,
            "process-owned rules changed after planning; rerun plan before applying"
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
            write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
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
    let mut keys = feedback.keys;
    keys.sort();
    let mut key_patterns = feedback.key_patterns;
    key_patterns.sort_by(|left, right| {
        (&left.prefix, &left.suffix, left.numeric_middle).cmp(&(
            &right.prefix,
            &right.suffix,
            right.numeric_middle,
        ))
    });
    let command = feedback.command.to_ascii_uppercase();
    let requested = BackgroundDependencyRuleConfig::Redis {
        name: feedback.name.clone(),
        ports: ports.clone(),
        command: command.clone(),
        keys: keys.clone(),
        key_patterns: key_patterns.clone(),
        key_prefix: feedback.key_prefix.clone(),
        key_suffix: feedback.key_suffix.clone(),
        initial_load_timeout_ms: feedback.initial_load_timeout_ms,
        fields: feedback.fields.clone(),
        source_revision: String::new(),
        source_evidence: feedback.source_evidence.clone(),
    };
    process_owned_dependencies::validate(std::slice::from_ref(&requested))?;

    let original_replay_report = read_file(&feedback.replay_report_path, "replay report")?;
    let evidence = parse_replay_evidence(
        &original_replay_report,
        &feedback.replay_report_path,
        &requested,
    )?;
    let RuleConfigPlan {
        original,
        updated,
        changed,
        diff,
        effective_name,
        reused_existing,
    } = plan_rule_config(&feedback.rules_path, requested)?;

    Ok(RedisBackgroundDependencyPlan {
        rules_path: feedback.rules_path.clone(),
        replay_report_path: feedback.replay_report_path.clone(),
        original_rules: original,
        original_replay_report,
        updated_rules: updated,
        dependency_evidence: evidence.files,
        report: RedisBackgroundDependencyReport {
            rules: feedback.rules_path,
            replay_report: feedback.replay_report_path,
            name: feedback.name,
            effective_name,
            reused_existing,
            protocol: "redis",
            ports,
            command,
            keys,
            key_patterns,
            key_prefix: feedback.key_prefix,
            key_suffix: feedback.key_suffix,
            initial_load_timeout_ms: feedback.initial_load_timeout_ms,
            fields: feedback.fields,
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
    requested: &BackgroundDependencyRuleConfig,
) -> Result<EvidenceMatch> {
    let BackgroundDependencyRuleConfig::Redis {
        ports,
        command,
        keys,
        key_patterns,
        ..
    } = requested
    else {
        unreachable!("Redis planner always constructs a Redis rule")
    };
    let report: ReplayEvidenceReport =
        crate::replay::report::parse_background_dependency_evidence(raw)
            .with_context(|| format!("failed to parse replay report {}", report_path.display()))?;
    ensure!(
        report.version == 6,
        "Redis process-owned dependency evidence requires replay report version 6"
    );
    ensure!(
        report.finalized,
        "process-owned dependency evidence requires a finalized replay report"
    );
    if matches!(command.as_str(), "HGET" | "HMGET") {
        return parse_global_bootstrap_evidence(report, report_path, requested);
    }
    ensure!(
        !report
            .redis
            .unsupported
            .iter()
            .chain(&report.redis.unsafe_events)
            .any(|event| ports.contains(&event.target.port)
                && event.command.eq_ignore_ascii_case(command)),
        "Redis background selector shares a configured port and command with unsupported or unsafe target traffic"
    );
    ensure!(
        !report.redis.unmatched.iter().any(|event| {
            ports.contains(&event.target.port) && event.command.eq_ignore_ascii_case(command)
        }),
        "Redis background selector shares a configured port and command with unmatched target traffic"
    );
    let unused_case = report
        .redis
        .unused_case
        .iter()
        .filter(|event| {
            ports.contains(&event.target.port) && event.command.eq_ignore_ascii_case(command)
        })
        .map(|event| (event.index, event))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        !unused_case.is_empty(),
        "Redis background selector matches no unused case exchange on the configured ports"
    );

    let mut files = Vec::new();
    let mut exchange_index = 0;
    let mut evidence = EvidenceAccumulator::default();
    let empty_unused = BTreeMap::new();
    if let Some(recorded) = report.global_dependencies_path {
        let path = resolve_evidence_path(report_path, &recorded);
        let contents = read_file(&path, "Global dependency evidence")?;
        scan_redis_dependency_file(
            &contents,
            &path,
            &empty_unused,
            None,
            &mut exchange_index,
            requested,
            &mut evidence,
        )?;
        files.push(snapshot_bytes(path, contents.as_bytes()));
    }
    for case in report.cases {
        let path = resolve_evidence_path(report_path, &case.dependencies_path);
        let contents = read_file(&path, "case dependency evidence")?;
        scan_redis_dependency_file(
            &contents,
            &path,
            &unused_case,
            Some(&case.case_id),
            &mut exchange_index,
            requested,
            &mut evidence,
        )?;
        files.push(snapshot_bytes(path, contents.as_bytes()));
    }
    ensure!(
        evidence.count > 0,
        "Redis background selector matches no unused case key in immutable dependency evidence"
    );
    if !keys.is_empty() {
        let expected_keys = keys
            .iter()
            .map(|key| key.as_bytes().to_vec())
            .collect::<BTreeSet<_>>();
        ensure!(
            evidence.matched_keys == expected_keys,
            "Redis {command} background selector must match every configured exact key in immutable case dependency evidence"
        );
    }
    ensure!(
        evidence.matched_patterns.len() == key_patterns.len(),
        "Redis {command} background selector must match every configured numeric key pattern in immutable case dependency evidence"
    );
    Ok(EvidenceMatch {
        count: evidence.count,
        case_ids: evidence.case_ids.into_iter().collect(),
        observed_ports: evidence.observed_ports.into_iter().collect(),
        files,
    })
}

fn parse_global_bootstrap_evidence(
    report: ReplayEvidenceReport,
    report_path: &Path,
    requested: &BackgroundDependencyRuleConfig,
) -> Result<EvidenceMatch> {
    let BackgroundDependencyRuleConfig::Redis {
        ports,
        command,
        keys,
        key_patterns,
        ..
    } = requested
    else {
        unreachable!("Redis planner always constructs a Redis rule")
    };
    ensure!(
        !report
            .redis
            .unsupported
            .iter()
            .chain(&report.redis.unsafe_events)
            .any(|event| ports.contains(&event.target.port)
                && event.command.eq_ignore_ascii_case(command)),
        "Redis bootstrap selector shares a configured port and command with unsupported or unsafe target traffic"
    );
    let recorded = report
        .global_dependencies_path
        .context("Redis bootstrap evidence requires global_dependencies_path")?;
    let path = resolve_evidence_path(report_path, &recorded);
    let contents = read_file(&path, "global bootstrap dependency evidence")?;
    let mut count = 0;
    let mut observed_ports = BTreeSet::new();
    let mut matched_keys = BTreeSet::new();
    let mut matched_patterns = BTreeSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!(
                "invalid dependency JSON at {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        if value.get("event_type").and_then(serde_json::Value::as_str) != Some("redis_exchange")
            || value
                .get("global_dependency_reason")
                .and_then(serde_json::Value::as_str)
                != Some("bootstrap_window")
        {
            continue;
        }
        let Some(port) = value
            .get("target_port")
            .and_then(serde_json::Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
        else {
            continue;
        };
        let Some(observed_command) = value.get("command").and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let args = decode_args(&value)?;
        if !redis_rule_matches(requested, port, observed_command, &args) {
            continue;
        }
        ensure!(
            value
                .get("replay_safe")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            "Redis bootstrap selector matches replay-unsafe evidence"
        );
        count += 1;
        observed_ports.insert(port);
        let key = &args[0];
        if matches_exact_redis_key(key, keys) {
            matched_keys.insert(key.clone());
        }
        for (index, pattern) in key_patterns.iter().enumerate() {
            if matches_redis_numeric_key_pattern(
                key,
                pattern.prefix.as_bytes(),
                pattern.suffix.as_bytes(),
            ) {
                matched_patterns.insert(index);
            }
        }
    }
    ensure!(
        count > 0,
        "Redis bootstrap selector matches no replay-safe bootstrap-window exchange"
    );
    let expected_keys = keys
        .iter()
        .map(|key| key.as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    ensure!(
        matched_keys == expected_keys,
        "Redis {command} bootstrap selector must match every configured exact key"
    );
    ensure!(
        matched_patterns.len() == key_patterns.len(),
        "Redis {command} bootstrap selector must match every configured numeric key pattern"
    );
    Ok(EvidenceMatch {
        count,
        case_ids: Vec::new(),
        observed_ports: observed_ports.into_iter().collect(),
        files: vec![snapshot_bytes(path, contents.as_bytes())],
    })
}

#[derive(Default)]
struct EvidenceAccumulator {
    count: usize,
    case_ids: BTreeSet<String>,
    observed_ports: BTreeSet<u16>,
    matched_keys: BTreeSet<Vec<u8>>,
    matched_patterns: BTreeSet<usize>,
}

fn scan_redis_dependency_file(
    contents: &str,
    path: &Path,
    unused: &BTreeMap<usize, &CommandUnusedEvidence>,
    expected_case_id: Option<&str>,
    exchange_index: &mut usize,
    requested: &BackgroundDependencyRuleConfig,
    evidence: &mut EvidenceAccumulator,
) -> Result<()> {
    for (line_index, line) in contents.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!(
                "invalid dependency JSON at {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        if value.get("event_type").and_then(serde_json::Value::as_str) != Some("redis_exchange") {
            continue;
        }
        let current_index = *exchange_index;
        *exchange_index += 1;
        let Some(recorded) = unused.get(&current_index) else {
            continue;
        };
        ensure!(
            recorded.case_id.as_deref() == expected_case_id,
            "replay report Redis exchange index {current_index} does not match its immutable dependency evidence scope"
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
        let args = decode_args(&value)?;
        if !redis_rule_matches(requested, recorded.target.port, &recorded.command, &args) {
            continue;
        }
        ensure!(
            value
                .get("replay_safe")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            "Redis background selector matches replay-unsafe evidence"
        );
        evidence.count += 1;
        if let Some(case_id) = expected_case_id {
            evidence.case_ids.insert(case_id.to_string());
        }
        evidence.observed_ports.insert(recorded.target.port);
        let key = &args[0];
        if let BackgroundDependencyRuleConfig::Redis {
            keys, key_patterns, ..
        } = requested
        {
            if matches_exact_redis_key(key, keys) {
                evidence.matched_keys.insert(key.clone());
            }
            for (index, pattern) in key_patterns.iter().enumerate() {
                if matches_redis_numeric_key_pattern(
                    key,
                    pattern.prefix.as_bytes(),
                    pattern.suffix.as_bytes(),
                ) {
                    evidence.matched_patterns.insert(index);
                }
            }
        }
    }
    Ok(())
}

fn decode_args(value: &serde_json::Value) -> Result<Vec<Vec<u8>>> {
    value
        .get("args")
        .and_then(serde_json::Value::as_array)
        .context("recorded Redis exchange is missing args")?
        .iter()
        .map(|arg| {
            let arg = arg
                .as_object()
                .context("recorded Redis argument must be an object")?;
            ensure!(
                arg.get("truncated").and_then(serde_json::Value::as_bool) == Some(false),
                "Redis bootstrap selector cannot use a truncated argument"
            );
            let encoding = arg
                .get("encoding")
                .and_then(serde_json::Value::as_str)
                .context("recorded Redis argument is missing its encoding")?;
            let data = arg
                .get("data")
                .and_then(serde_json::Value::as_str)
                .context("recorded Redis argument is missing its data")?;
            match encoding {
                "utf8" => Ok(data.as_bytes().to_vec()),
                "base64" => STANDARD
                    .decode(data.as_bytes())
                    .context("recorded Redis argument contains invalid base64"),
                other => {
                    anyhow::bail!("recorded Redis argument has unsupported encoding {other:?}")
                }
            }
        })
        .collect()
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
