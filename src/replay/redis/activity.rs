//! Explicit JSON activity refresh lifetimes; creation/deletion remain finite.
use super::*;
use crate::policy::{Database, NativeEffect, Protocol, TimeContract};
use serde_json::Value;

mod lifecycle;
mod runtime;
mod source;
#[cfg(test)]
mod tests;
mod value;

const MAX_KEYS: usize = 128;
const MAX_CALLS: usize = 4096;
const MAX_BYTES: usize = crate::value_limits::MAX_VALUE_BYTES;

#[derive(Debug, Default)]
pub(super) struct ActivityRefreshes {
    prepared: BTreeSet<String>,
    profiles: Vec<Profile>,
    owned: BTreeMap<String, BTreeSet<(Uuid, u64)>>,
    pending: BTreeMap<Uuid, usize>,
    calls: BTreeMap<String, usize>,
    charged: BTreeSet<usize>,
    audits: Vec<ActivityAudit>,
    omitted: usize,
}

#[derive(Debug)]
struct Profile {
    case: String,
    rule: String,
    target: TargetKey,
    database: i64,
    username: Option<String>,
    resp_version: u8,
    key: Vec<u8>,
    lifetimes: Vec<Lifetime>,
    current: Option<Current>,
    failed: bool,
}

#[derive(Debug)]
struct Lifetime {
    creation: usize,
    deletion: Option<usize>,
    reads: Vec<usize>,
    writes: Vec<usize>,
    fields: Vec<(String, TimeContract)>,
    reference: Value,
    ttl_args: Vec<Vec<u8>>,
    ttl_seconds: u64,
}

impl Lifetime {
    fn eligible(&self) -> bool {
        !self.reads.is_empty() && !self.writes.is_empty()
    }
}

#[derive(Debug)]
struct Current {
    lifetime: usize,
    key: Vec<u8>,
    bytes: Vec<u8>,
    value: Value,
    established_at: tokio::time::Instant,
    reads: usize,
}

#[derive(Debug, Clone)]
pub(super) struct Prepared {
    kind: Completion,
    profile: usize,
    lifetime: usize,
    token: Uuid,
    command: String,
    witness: usize,
    observation: Option<Uuid>,
    event_index: Option<usize>,
    target_key_fingerprint: String,
    target_value_fingerprint: String,
}

#[derive(Debug, Clone, Copy)]
enum Completion {
    Create,
    Delete,
    Read,
    Refresh,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct ActivityAudit {
    rule_id: String,
    case_id: String,
    command: String,
    target_event_index: Option<usize>,
    target_observation: Option<Uuid>,
    source_key_fingerprint: String,
    target_key_fingerprint: String,
    target_value_fingerprint: String,
    source_creation: super::super::report::command::CommandExchangeRefReport,
    source_witness: super::super::report::command::CommandExchangeRefReport,
    covered_source_observations: usize,
}

impl ActivityRefreshes {
    pub(super) fn owns(&self, e: &ReplayExchange) -> bool {
        e.source == ReplaySource::Case
            && e.case_id.as_deref().is_some_and(|case| {
                self.owned.get(case).is_some_and(|owned| {
                    owned.contains(&(e.record.connection_id, e.record.sequence))
                })
            })
    }
    pub(super) fn has_in_flight(&self) -> bool {
        !self.pending.is_empty()
    }
    pub(super) fn in_flight_diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"count":self.pending.len(), "cases":self.pending.values().take(4)
            .map(|&i| self.profiles[i].case.as_str()).collect::<Vec<_>>(),
            "omitted":self.pending.len().saturating_sub(4)})
    }
    pub(super) fn reports(&self) -> Vec<ActivityAudit> {
        self.audits.clone()
    }
    pub(super) fn omitted(&self) -> usize {
        self.omitted
    }
    pub(super) fn check_case_addition(
        &self,
        source: ReplaySource,
        case: Option<&str>,
    ) -> Result<()> {
        ensure!(
            source != ReplaySource::Case || case.is_none_or(|c| !self.prepared.contains(c)),
            "cannot extend a prepared activity refresh Case inventory"
        );
        Ok(())
    }
    pub(super) fn check_inventory_addition(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
        source: ReplaySource,
        case_id: Option<&str>,
    ) -> Result<()> {
        ensure!(
            !self.profiles.iter().any(|p| p.database == record.database
                && target_matches(&p.target, &record.target_host, record.target_port)
                && super::key_access::touches(&record.command, args, &p.key)
                && !super::case_scope::is_other_ordinary_case(&p.case, source, case_id, record)),
            "cannot add overlapping activity refresh inventory after Source preparation"
        );
        Ok(())
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    crate::policy_evidence::digest(bytes)
}

pub(in crate::replay) fn validate_source(
    contracts: &crate::replay::policy::request_contract::RequestContracts,
    cases: &[crate::replay::policy::native_projection::NativeSourceCase<'_>],
) -> Result<BTreeMap<String, usize>> {
    let mut state = super::native_source::source_inventory(contracts, cases, |effect| {
        matches!(effect, NativeEffect::RedisActivityRefresh(_))
    })?;
    for case in cases {
        state.prepare_activity_case(case.id)?;
    }
    let mut counts = BTreeMap::new();
    for profile in state.activity_refresh.profiles {
        *counts.entry(profile.rule).or_default() += profile
            .lifetimes
            .iter()
            .filter(|l| l.eligible())
            .map(|l| l.reads.len() + l.writes.len())
            .sum::<usize>();
    }
    Ok(counts)
}
