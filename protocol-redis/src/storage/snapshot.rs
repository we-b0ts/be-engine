//! Immutable Redis snapshot equivalence and complete bootstrap coverage.
use crate::keys::matches_redis_numeric_key_pattern;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use traffic_model::{DependencyExchangeOutcome, attribution::DependencyScope as ReplaySource};
use uuid::Uuid;

pub const MAX_MATCHING_EXCHANGES: usize = 16_384;
pub const MAX_MATCHING_BYTES: usize = 2 * traffic_value::MAX_VALUE_BYTES;

/// The host supplies an authorized selector and current rule ownership.
/// Native equivalence and complete physical-key coverage are proven here.
pub trait Rule {
    fn name(&self) -> &str;
    fn matches(&self, exchange: &SnapshotEvidence) -> bool;
    fn keys(&self) -> &[String];
    fn key_patterns(&self) -> impl Iterator<Item = (&str, &str)>;
    fn owns_seed(&self, recorded: &str) -> bool;
}

#[derive(Debug)]
pub struct Analysis {
    pub reusable_seeds: usize,
    pub derived_seeds: usize,
    pub matching_global_exchanges: usize,
    pub matching_case_exchanges: usize,
    pub reusable_replay_indexes: Vec<usize>,
    pub evidence: Vec<FingerprintEvidence>,
}

#[derive(Debug, Clone)]
pub struct SnapshotEvidence {
    pub replay_index: Option<usize>,
    pub source: ReplaySource,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub target_host: String,
    pub target_port: u16,
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub command: String,
    pub args: Vec<Vec<u8>>,
    pub response_kind: String,
    pub response: Vec<u8>,
    pub outcome: DependencyExchangeOutcome,
    pub replay_safe: bool,
    pub cache_snapshot_rule: Option<String>,
    pub cache_snapshot_hit: bool,
    pub session_setup: bool,
    pub run_owner_kind: Option<String>,
}

impl SnapshotEvidence {
    pub fn from_storage(index: usize, exchange: &impl super::StorageExchange) -> Result<Self> {
        Ok(Self::project(
            Some(index),
            exchange.source(),
            exchange.native_record(),
            exchange.arguments().to_vec(),
            exchange.response_bytes()?,
        ))
    }

    pub fn from_record(
        replay_index: Option<usize>,
        source: ReplaySource,
        record: &crate::recorded::RecordedExchange,
    ) -> Result<Self> {
        let args = record
            .args
            .iter()
            .map(|capture| capture.decode())
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::project(
            replay_index,
            source,
            record,
            args,
            record.response.decode()?,
        ))
    }

    fn project(
        replay_index: Option<usize>,
        source: ReplaySource,
        record: &crate::recorded::RecordedExchange,
        args: Vec<Vec<u8>>,
        response: Vec<u8>,
    ) -> Self {
        Self {
            replay_index,
            source,
            connection_id: record.connection_id,
            sequence: record.sequence,
            target_host: record.target_host.clone(),
            target_port: record.target_port,
            resp_version: record.resp_version,
            database: record.database,
            username: record.username.clone(),
            command: record.command.clone(),
            args,
            response_kind: record.response_kind.clone(),
            response,
            outcome: record.outcome,
            replay_safe: record.replay_safe,
            cache_snapshot_rule: record.cache_snapshot_rule.clone(),
            cache_snapshot_hit: record.cache_snapshot_hit,
            session_setup: record.session_setup,
            run_owner_kind: record.run_owner_kind().map(str::to_owned),
        }
    }
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FingerprintEvidence {
    source: &'static str,
    connection_id: String,
    sequence: u64,
    identity: SnapshotIdentity,
    response_kind: String,
    response: Vec<u8>,
    run_owner_kind: Option<String>,
    cache_snapshot_rule: Option<String>,
}

#[derive(Default)]
pub struct EvidenceCollector {
    pub entries: Vec<SnapshotEvidence>,
    bytes: usize,
}

impl EvidenceCollector {
    pub fn push(&mut self, entry: SnapshotEvidence) -> Result<()> {
        ensure!(
            self.entries.len() < MAX_MATCHING_EXCHANGES,
            "Redis snapshot evidence exceeds the {MAX_MATCHING_EXCHANGES} exchange evidence limit"
        );
        let bytes = entry
            .args
            .iter()
            .try_fold(self.bytes, |total, arg| total.checked_add(arg.len()))
            .and_then(|total| total.checked_add(entry.response.len()))
            .context("Redis snapshot evidence byte count overflowed")?;
        ensure!(
            bytes <= MAX_MATCHING_BYTES,
            "Redis snapshot evidence exceeds the {MAX_MATCHING_BYTES} byte evidence limit"
        );
        self.bytes = bytes;
        self.entries.push(entry);
        Ok(())
    }
}

pub fn analyze(rule: &impl Rule, evidence: &[SnapshotEvidence]) -> Result<Analysis> {
    let mut groups = BTreeMap::<SnapshotIdentity, Vec<&SnapshotEvidence>>::new();
    let mut matching_bytes = 0_usize;
    let mut matching_global_exchanges = 0_usize;
    let mut matching_case_exchanges = 0_usize;
    for exchange in evidence {
        if !rule.matches(exchange) {
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
            ReplaySource::Unattributed => continue,
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
                    .is_some_and(|name| rule.owns_seed(name))
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
    Ok(Analysis {
        reusable_seeds: groups.len(),
        derived_seeds,
        matching_global_exchanges,
        matching_case_exchanges,
        reusable_replay_indexes,
        evidence: fingerprint_evidence(&groups),
    })
}

fn ensure_safe_snapshot_exchange(rule: &impl Rule, exchange: &SnapshotEvidence) -> Result<()> {
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
                exchange
                    .cache_snapshot_rule
                    .as_deref()
                    .is_some_and(|name| { rule.owns_seed(name) }),
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
        target_host: traffic_protocol::observation::normalize_host(&exchange.target_host),
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
    rule: &impl Rule,
    identities: impl Iterator<Item = &'a SnapshotIdentity>,
) -> Result<()> {
    let observed_keys = identities
        .filter_map(|identity| identity.args.first().cloned())
        .collect::<BTreeSet<_>>();
    let missing_keys = rule
        .keys()
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
    let missing_patterns = rule
        .key_patterns()
        .filter(|(prefix, suffix)| {
            !observed_keys.iter().any(|key| {
                matches_redis_numeric_key_pattern(key, prefix.as_bytes(), suffix.as_bytes())
            })
        })
        .map(|(prefix, suffix)| format!("{prefix}*{suffix}"))
        .collect::<Vec<_>>();
    ensure!(
        missing_patterns.is_empty(),
        "Redis snapshot rule {:?} has no Global seed for numeric key patterns: {}",
        rule.name(),
        missing_patterns.join(", ")
    );
    Ok(())
}

fn fingerprint_evidence(
    groups: &BTreeMap<SnapshotIdentity, Vec<&SnapshotEvidence>>,
) -> Vec<FingerprintEvidence> {
    let mut evidence = groups
        .iter()
        .flat_map(|(identity, entries)| {
            entries.iter().map(move |entry| FingerprintEvidence {
                source: match entry.source {
                    ReplaySource::Startup | ReplaySource::Process => "global",
                    ReplaySource::Case => "case",
                    ReplaySource::Unattributed => "unattributed",
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
    evidence
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
