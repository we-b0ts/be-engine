use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use serde::Serialize;
use uuid::Uuid;

use super::{RecordedExchange, RedisReplayState, ReplayExchange};
use crate::DependencyExchangeOutcome;
use crate::config::process_owned_dependencies::{
    matches_redis_numeric_key_pattern, redis_rule_matches,
};
use crate::config::{BackgroundDependencyRuleConfig, SourceTrafficPolicyConfig};
use crate::replay::dependencies::DependencyRecord;
use crate::replay::model::ReplaySource;
use crate::replay::report::command::CommandSnapshotOverlayReport;

const MAX_MATCHING_EXCHANGES: usize = 16_384;
const MAX_MATCHING_BYTES: usize = 2 * crate::value_limits::MAX_VALUE_BYTES;
mod loading;

#[derive(Debug, Clone)]
struct SnapshotEvidence {
    replay_index: Option<usize>,
    source: ReplaySource,
    connection_id: Uuid,
    sequence: u64,
    target_host: String,
    target_port: u16,
    resp_version: u8,
    database: i64,
    username: Option<String>,
    command: String,
    args: Vec<Vec<u8>>,
    response_kind: String,
    response: Vec<u8>,
    outcome: DependencyExchangeOutcome,
    replay_safe: bool,
    cache_snapshot_rule: Option<String>,
    cache_snapshot_hit: bool,
    session_setup: bool,
    run_owner_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct SnapshotIdentity {
    target_host: String,
    target_port: u16,
    resp_version: u8,
    database: i64,
    username: Option<String>,
    command: String,
    args: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct SnapshotAnalysis {
    report: CommandSnapshotOverlayReport,
    reusable_replay_indexes: Vec<usize>,
}

#[derive(Serialize)]
struct FingerprintInput<'a> {
    case_source: &'a str,
    rule: &'a BackgroundDependencyRuleConfig,
    evidence: Vec<FingerprintEvidence>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct FingerprintEvidence {
    source: &'static str,
    connection_id: String,
    sequence: u64,
    identity: SnapshotIdentity,
    response_kind: String,
    response: Vec<u8>,
    run_owner_kind: Option<String>,
    cache_snapshot_rule: Option<String>,
}

pub(crate) fn inspect_case_source_snapshot_overlay(
    case_source: &Path,
    source_traffic_policy: &Path,
    rule_name: &str,
) -> Result<CommandSnapshotOverlayReport> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let policy = SourceTrafficPolicyConfig::load(source_traffic_policy)?;
    let rule = policy
        .process_owned_dependencies
        .iter()
        .find(|rule| rule.name() == rule_name)
        .with_context(|| format!("process-owned dependency rule {rule_name:?} is absent"))?;
    ensure!(
        rule.uses_redis_snapshot(),
        "process-owned dependency rule {rule_name:?} does not authorize Redis snapshots"
    );
    let global = super::super::find_run_level_dependencies(&case_source)
        .0
        .with_context(|| {
            format!(
                "case source {} has no global-dependencies.jsonl",
                case_source.display()
            )
        })?;
    let mut evidence = loading::EvidenceCollector::default();
    loading::read_snapshot_evidence(&global, ReplaySource::Startup, rule, &mut evidence)?;
    for path in crate::case_group::published_case_dependency_paths(&case_source)? {
        loading::read_snapshot_evidence(&path, ReplaySource::Case, rule, &mut evidence)?;
    }
    let binding = case_source.to_string_lossy();
    Ok(analyze_snapshot_evidence(&binding, rule, &evidence.entries)?.report)
}

impl RedisReplayState {
    pub(in crate::replay) fn apply_snapshot_overlays(
        &mut self,
        case_source: &Path,
        rules: &[BackgroundDependencyRuleConfig],
    ) {
        let binding = case_source.to_string_lossy();
        for rule in rules {
            if !rule.uses_redis_snapshot() {
                continue;
            }
            let evidence = loading::replay_evidence(&self.exchanges, rule);
            let evidence = match evidence {
                Ok(evidence) => evidence,
                Err(error) => {
                    self.snapshot_overlay_warnings
                        .push(format!("Redis snapshot evidence unavailable: {error:#}"));
                    continue;
                }
            };
            match analyze_snapshot_evidence(&binding, rule, &evidence) {
                Ok(analysis) => {
                    for index in analysis.reusable_replay_indexes {
                        if let Some(exchange) = self.exchanges.get_mut(index) {
                            exchange.reusable_snapshot = true;
                            exchange.connection_independent = true;
                        }
                    }
                    self.snapshot_overlays.push(analysis.report);
                }
                Err(error) => self.snapshot_overlay_warnings.push(format!(
                    "Redis snapshot overlay for rule {:?} was not derived: {error:#}",
                    rule.name()
                )),
            }
        }
    }
}

fn evidence_from_replay(index: usize, exchange: &ReplayExchange) -> Result<SnapshotEvidence> {
    Ok(SnapshotEvidence {
        replay_index: Some(index),
        source: exchange.source,
        connection_id: exchange.record.connection_id,
        sequence: exchange.record.sequence,
        target_host: exchange.record.target_host.clone(),
        target_port: exchange.record.target_port,
        resp_version: exchange.record.resp_version,
        database: exchange.record.database,
        username: exchange.record.username.clone(),
        command: exchange.record.command.clone(),
        args: exchange.args.clone(),
        response_kind: exchange.record.response_kind.clone(),
        response: exchange.response_bytes()?,
        outcome: exchange.record.outcome,
        replay_safe: exchange.record.replay_safe,
        cache_snapshot_rule: exchange.record.cache_snapshot_rule.clone(),
        cache_snapshot_hit: exchange.record.cache_snapshot_hit,
        session_setup: exchange.record.session_setup,
        run_owner_kind: exchange.record.run_owner_kind().map(str::to_owned),
    })
}

fn evidence_from_record(
    replay_index: Option<usize>,
    source: ReplaySource,
    record: RecordedExchange,
) -> Result<SnapshotEvidence> {
    let args = record
        .args
        .iter()
        .map(super::RecordedCapture::decode)
        .collect::<Result<Vec<_>>>()?;
    let response = record.response.decode()?;
    let run_owner_kind = record.run_owner_kind().map(str::to_owned);
    Ok(SnapshotEvidence {
        replay_index,
        source,
        connection_id: record.connection_id,
        sequence: record.sequence,
        target_host: record.target_host,
        target_port: record.target_port,
        resp_version: record.resp_version,
        database: record.database,
        username: record.username,
        command: record.command,
        args,
        response_kind: record.response_kind,
        response,
        outcome: record.outcome,
        replay_safe: record.replay_safe,
        cache_snapshot_rule: record.cache_snapshot_rule,
        cache_snapshot_hit: record.cache_snapshot_hit,
        session_setup: record.session_setup,
        run_owner_kind,
    })
}

fn analyze_snapshot_evidence(
    case_source: &str,
    rule: &BackgroundDependencyRuleConfig,
    evidence: &[SnapshotEvidence],
) -> Result<SnapshotAnalysis> {
    let mut groups = BTreeMap::<SnapshotIdentity, Vec<&SnapshotEvidence>>::new();
    let mut matching_bytes = 0_usize;
    let mut matching_global_exchanges = 0_usize;
    let mut matching_case_exchanges = 0_usize;
    for exchange in evidence {
        if !redis_rule_matches(
            rule,
            exchange.target_port,
            &exchange.command,
            &exchange.args,
        ) {
            continue;
        }
        ensure_safe_snapshot_exchange(rule, exchange)?;
        matching_bytes = matching_bytes
            .checked_add(exchange.response.len())
            .and_then(|total| {
                exchange
                    .args
                    .iter()
                    .try_fold(total, |total, arg| total.checked_add(arg.len()))
            })
            .context("Redis snapshot evidence byte count overflowed")?;
        ensure!(
            matching_bytes <= MAX_MATCHING_BYTES,
            "Redis snapshot rule {:?} exceeds the {} byte evidence limit",
            rule.name(),
            MAX_MATCHING_BYTES
        );
        match exchange.source {
            ReplaySource::Startup | ReplaySource::Process => matching_global_exchanges += 1,
            ReplaySource::Case => matching_case_exchanges += 1,
        }
        let identity = snapshot_identity(exchange);
        groups.entry(identity).or_default().push(exchange);
    }
    let matching_exchanges = matching_global_exchanges + matching_case_exchanges;
    ensure!(
        matching_exchanges > 0,
        "Redis snapshot rule {:?} matches no immutable evidence",
        rule.name()
    );
    ensure!(
        matching_exchanges <= MAX_MATCHING_EXCHANGES,
        "Redis snapshot rule {:?} exceeds the {} exchange evidence limit",
        rule.name(),
        MAX_MATCHING_EXCHANGES
    );

    ensure_rule_coverage(rule, groups.keys())?;
    let mut reusable_replay_indexes = Vec::new();
    let mut derived_seeds = 0_usize;
    for (identity, entries) in &groups {
        let expected = entries.first().expect("snapshot group is non-empty");
        ensure!(
            entries.iter().all(|entry| {
                entry.response_kind == expected.response_kind && entry.response == expected.response
            }),
            "Redis snapshot rule {:?} has conflicting responses for {}",
            rule.name(),
            display_identity(identity)
        );
        let explicit = entries.iter().copied().find(|entry| {
            entry.source.is_run_owned()
                && entry.run_owner_kind.as_deref() == Some("process")
                && entry
                    .cache_snapshot_rule
                    .as_deref()
                    .is_some_and(|name| super::snapshot_seed::owner_name_matches(name, rule.name()))
        });
        let bootstrap = entries.iter().copied().find(|entry| {
            entry.source.is_run_owned() && entry.run_owner_kind.as_deref() == Some("startup")
        });
        let seed = explicit.or(bootstrap).with_context(|| {
            format!(
                "Redis snapshot rule {:?} has no Global bootstrap seed for {}",
                rule.name(),
                display_identity(identity)
            )
        })?;
        if explicit.is_none() {
            derived_seeds += 1;
        }
        if let Some(index) = seed.replay_index {
            reusable_replay_indexes.push(index);
        }
    }
    let evidence_fingerprint = evidence_fingerprint(case_source, rule, &groups)?;
    Ok(SnapshotAnalysis {
        report: CommandSnapshotOverlayReport {
            rule_name: rule.name().to_string(),
            evidence_fingerprint,
            reusable_seeds: groups.len(),
            derived_seeds,
            matching_global_exchanges,
            matching_case_exchanges,
        },
        reusable_replay_indexes,
    })
}

fn ensure_safe_snapshot_exchange(
    rule: &BackgroundDependencyRuleConfig,
    exchange: &SnapshotEvidence,
) -> Result<()> {
    let rule_name = rule.name();
    ensure!(
        exchange.replay_safe,
        "Redis snapshot rule {rule_name:?} matches replay-unsafe evidence"
    );
    ensure!(
        !exchange.cache_snapshot_hit,
        "Redis snapshot rule {rule_name:?} matches a diagnostic snapshot hit"
    );
    ensure!(
        !exchange.session_setup,
        "Redis snapshot rule {rule_name:?} matches session setup evidence"
    );
    ensure!(
        !exchange.target_host.trim().is_empty()
            && matches!(exchange.resp_version, 2 | 3)
            && exchange.database >= 0
            && exchange.sequence > 0
            && !exchange.command.trim().is_empty(),
        "Redis snapshot rule {rule_name:?} matches incomplete session identity"
    );
    ensure!(
        exchange.outcome == DependencyExchangeOutcome::Response
            && !exchange.response_kind.eq_ignore_ascii_case("error"),
        "Redis snapshot rule {rule_name:?} matches a failed or error response"
    );
    if exchange.source.is_run_owned() {
        ensure!(
            matches!(
                exchange.run_owner_kind.as_deref(),
                Some("startup" | "process")
            ),
            "Redis snapshot rule {rule_name:?} matches ambiguous Global evidence"
        );
        if exchange.run_owner_kind.as_deref() == Some("process") {
            ensure!(
                exchange.cache_snapshot_rule.as_deref().is_some_and(|name| {
                    super::snapshot_seed::owner_name_matches(name, rule_name)
                }),
                "Redis snapshot rule {rule_name:?} matches a Global seed owned by another rule"
            );
        }
    } else {
        ensure!(
            exchange.cache_snapshot_rule.is_none() && exchange.run_owner_kind.is_none(),
            "Redis snapshot rule {rule_name:?} matches case evidence with Global snapshot metadata"
        );
    }
    Ok(())
}

fn snapshot_identity(exchange: &SnapshotEvidence) -> SnapshotIdentity {
    SnapshotIdentity {
        target_host: crate::replay::normalize_host(&exchange.target_host),
        target_port: exchange.target_port,
        resp_version: exchange.resp_version,
        database: exchange.database,
        username: exchange
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase),
        command: exchange.command.to_ascii_uppercase(),
        args: exchange.args.clone(),
    }
}

fn ensure_rule_coverage<'a>(
    rule: &BackgroundDependencyRuleConfig,
    identities: impl Iterator<Item = &'a SnapshotIdentity>,
) -> Result<()> {
    let BackgroundDependencyRuleConfig::Redis {
        keys, key_patterns, ..
    } = rule
    else {
        unreachable!("snapshot overlays only analyze Redis rules")
    };
    let observed_keys = identities
        .filter_map(|identity| identity.args.first().cloned())
        .collect::<BTreeSet<_>>();
    let missing_keys = keys
        .iter()
        .filter(|key| !observed_keys.contains(key.as_bytes()))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        missing_keys.is_empty(),
        "Redis snapshot rule {:?} has no Global seed for exact keys: {}",
        rule.name(),
        missing_keys.join(", ")
    );
    let missing_patterns = key_patterns
        .iter()
        .filter(|pattern| {
            !observed_keys.iter().any(|key| {
                matches_redis_numeric_key_pattern(
                    key,
                    pattern.prefix.as_bytes(),
                    pattern.suffix.as_bytes(),
                )
            })
        })
        .map(|pattern| format!("{}*{}", pattern.prefix, pattern.suffix))
        .collect::<Vec<_>>();
    ensure!(
        missing_patterns.is_empty(),
        "Redis snapshot rule {:?} has no Global seed for numeric key patterns: {}",
        rule.name(),
        missing_patterns.join(", ")
    );
    Ok(())
}

fn evidence_fingerprint(
    case_source: &str,
    rule: &BackgroundDependencyRuleConfig,
    groups: &BTreeMap<SnapshotIdentity, Vec<&SnapshotEvidence>>,
) -> Result<String> {
    let mut evidence = groups
        .iter()
        .flat_map(|(identity, entries)| {
            entries.iter().map(move |entry| FingerprintEvidence {
                source: match entry.source {
                    ReplaySource::Startup | ReplaySource::Process => "global",
                    ReplaySource::Case => "case",
                },
                connection_id: entry.connection_id.to_string(),
                sequence: entry.sequence,
                identity: identity.clone(),
                response_kind: entry.response_kind.clone(),
                response: entry.response.clone(),
                run_owner_kind: entry.run_owner_kind.clone(),
                cache_snapshot_rule: entry.cache_snapshot_rule.clone(),
            })
        })
        .collect::<Vec<_>>();
    evidence.sort();
    let payload = serde_json::to_vec(&FingerprintInput {
        case_source,
        rule,
        evidence,
    })?;
    Ok(crate::verification_progress::fingerprint(&payload))
}

fn display_identity(identity: &SnapshotIdentity) -> String {
    format!(
        "{}:{} db={} command={} args={}",
        identity.target_host,
        identity.target_port,
        identity.database,
        identity.command,
        identity.args.len()
    )
}

#[cfg(test)]
mod tests;
