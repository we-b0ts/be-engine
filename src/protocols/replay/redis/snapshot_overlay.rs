use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use serde::Serialize;

use super::{RecordedExchange, RedisReplayState, ReplayExchange};
use crate::config::process_owned_dependencies::redis_rule_matches;
use crate::config::{BackgroundDependencyRuleConfig, SourceTrafficPolicyConfig};
use crate::protocols::replay::source::DependencyRecord;
use crate::replay::report::command::CommandSnapshotOverlayReport;
use traffic_replay::ReplaySource;

mod loading;

use traffic_protocol_redis::storage::snapshot::{
    self as native, FingerprintEvidence, MAX_MATCHING_BYTES, SnapshotEvidence,
};

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
    let global = crate::replay::find_run_level_dependencies(&case_source)
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
    pub(crate) fn apply_snapshot_overlays(
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

fn evidence_from_record(
    replay_index: Option<usize>,
    source: ReplaySource,
    record: RecordedExchange,
) -> Result<SnapshotEvidence> {
    SnapshotEvidence::from_record(replay_index, source, &record.native)
}

fn analyze_snapshot_evidence(
    case_source: &str,
    rule: &BackgroundDependencyRuleConfig,
    evidence: &[SnapshotEvidence],
) -> Result<SnapshotAnalysis> {
    let analysis = native::analyze(&Selection(rule), evidence)?;
    let payload = serde_json::to_vec(&FingerprintInput {
        case_source,
        rule,
        evidence: analysis.evidence,
    })?;
    Ok(SnapshotAnalysis {
        report: CommandSnapshotOverlayReport {
            rule_name: rule.name().to_owned(),
            evidence_fingerprint: crate::verification_progress::fingerprint(&payload),
            reusable_seeds: analysis.reusable_seeds,
            derived_seeds: analysis.derived_seeds,
            matching_global_exchanges: analysis.matching_global_exchanges,
            matching_case_exchanges: analysis.matching_case_exchanges,
        },
        reusable_replay_indexes: analysis.reusable_replay_indexes,
    })
}

struct Selection<'a>(&'a BackgroundDependencyRuleConfig);

impl native::Rule for Selection<'_> {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn matches(&self, exchange: &SnapshotEvidence) -> bool {
        redis_rule_matches(
            self.0,
            exchange.target_port,
            &exchange.command,
            &exchange.args,
        )
    }

    fn keys(&self) -> &[String] {
        let BackgroundDependencyRuleConfig::Redis { keys, .. } = self.0 else {
            unreachable!("snapshot overlays only analyze Redis rules")
        };
        keys
    }

    fn key_patterns(&self) -> impl Iterator<Item = (&str, &str)> {
        let BackgroundDependencyRuleConfig::Redis { key_patterns, .. } = self.0 else {
            unreachable!("snapshot overlays only analyze Redis rules")
        };
        key_patterns
            .iter()
            .map(|pattern| (pattern.prefix.as_str(), pattern.suffix.as_str()))
    }

    fn owns_seed(&self, recorded: &str) -> bool {
        super::snapshot_seed::owner_name_matches(recorded, self.0.name())
    }
}

#[cfg(test)]
mod tests;
