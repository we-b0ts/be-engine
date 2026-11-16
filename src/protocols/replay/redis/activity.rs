//! Explicit JSON activity refresh lifetimes; creation/deletion remain finite.
use super::*;
use crate::policy::{Database, NativeEffect, Protocol, TimeContract};
use serde_json::Value;

mod lifecycle;
mod read_barrier;
mod runtime;
mod source;
#[cfg(test)]
pub(in crate::protocols::replay::redis) mod tests;
mod value;

const MAX_KEYS: usize = 128;
const MAX_CALLS: usize = 4096;
const MAX_BYTES: usize = crate::value_limits::MAX_VALUE_BYTES;
const READ_REQUIRED: &str = "activity SET requires a successfully delivered current-value GET";

#[derive(Debug, Default)]
pub(super) struct ActivityRefreshes {
    prepared: BTreeSet<String>,
    profiles: Vec<Profile>,
    owned: BTreeMap<String, BTreeSet<(Uuid, u64)>>,
    pending: BTreeMap<Uuid, Pending>,
    calls: BTreeMap<String, usize>,
    charged: BTreeSet<usize>,
    audits: Vec<ActivityAudit>,
    omitted: usize,
}

#[derive(Debug)]
struct Profile {
    source: SourceProfile,
    current: Option<Current>,
    failed: bool,
}

type SourceProfile =
    traffic_protocol_redis::storage::activity::Profile<Value, Vec<(String, TimeContract)>>;

impl std::ops::Deref for Profile {
    type Target = SourceProfile;

    fn deref(&self) -> &Self::Target {
        &self.source
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

#[derive(Debug, Clone, Copy)]
struct Pending {
    profile: usize,
    lifetime: usize,
    kind: Completion,
    event_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ActivityAudit {
    rule_id: String,
    case_id: String,
    command: String,
    target_event_index: Option<usize>,
    target_observation: Option<Uuid>,
    source_key_fingerprint: String,
    target_key_fingerprint: String,
    target_value_fingerprint: String,
    source_creation: crate::replay::report::command::CommandExchangeRefReport,
    source_witness: crate::replay::report::command::CommandExchangeRefReport,
    covered_source_observations: usize,
}

impl ActivityRefreshes {
    pub(super) fn owns(&self, e: &ReplayExchange) -> bool {
        e.source == ReplaySource::Case
            && e.case_id.as_deref().is_some_and(|case| {
                self.owned.get(case).is_some_and(|owned| {
                    owned.contains(&(e.record.native.connection_id, e.record.native.sequence))
                })
            })
    }
    pub(crate) fn has_in_flight(&self) -> bool {
        !self.pending.is_empty()
    }
    pub(super) fn in_flight_diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"count":self.pending.len(), "cases":self.pending.values().take(4)
            .map(|p| self.profiles[p.profile].case.as_str()).collect::<Vec<_>>(),
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
            !self
                .profiles
                .iter()
                .any(|p| p.database == record.native.database
                    && target_matches(
                        &p.target,
                        &record.native.target_host,
                        record.native.target_port
                    )
                    && super::key_access::touches(&record.native.command, args, &p.key)
                    && !super::case_scope::is_other_ordinary_case(
                        &p.case, source, case_id, record
                    )),
            "cannot add overlapping activity refresh inventory after Source preparation"
        );
        Ok(())
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    crate::policy_evidence::digest(bytes)
}

pub(crate) fn validate_source(
    contracts: &crate::policy::runtime::request_contract::RequestContracts,
    cases: &[crate::policy::runtime::native_projection::NativeSourceCase<'_>],
) -> Result<BTreeMap<String, usize>> {
    let mut state = super::native_source::source_inventory(contracts, cases, |effect| {
        matches!(effect, NativeEffect::RedisActivityRefresh(_))
    })?;
    for case in cases {
        state.prepare_activity_case(case.id)?;
    }
    let mut counts = BTreeMap::new();
    for profile in state.activity_refresh.profiles {
        *counts.entry(profile.source.rule).or_default() += profile
            .lifetimes
            .iter()
            .filter(|l| l.eligible())
            .map(|l| l.reads.len() + l.writes.len())
            .sum::<usize>();
    }
    Ok(counts)
}
