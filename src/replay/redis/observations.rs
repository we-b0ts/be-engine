//! Source-proven observations of a key's state, separate from its mutation lane.
//! Reads/refreshes may repeat or coalesce inside a lifetime; mutations stay finite.
use super::*;
use crate::policy::{Database, NativeEffect, Protocol};
use crate::replay::command_matching::CommandExchangeScope;
use crate::replay::report::command::CommandMatchDiagnostic;
use sha2::{Digest, Sha256};
mod absence;
mod closed_expiry;
#[cfg(test)]
mod recorded_tests;
mod refresh_barrier;
mod source;
pub(super) use source::validate_causal_order;
#[cfg(test)]
pub(super) mod tests;

const MAX_KEYS: usize = 128;
const MAX_OBSERVATIONS: usize = 4096;
const MAX_CALLS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Read,
    AbsentRead,
    Expiry,
}

impl Kind {
    fn is_read(self) -> bool {
        matches!(self, Self::Read | Self::AbsentRead)
    }
}

#[derive(Debug)]
struct Epoch {
    mutation: Option<usize>,
    observations: Vec<usize>,
}

#[derive(Debug)]
struct Profile {
    case: String,
    rule: String,
    kind: Kind,
    target: TargetKey,
    database: i64,
    username: Option<String>,
    resp_version: u8,
    key: Vec<u8>,
    finite_prefix: Vec<usize>,
    initial_accesses: Vec<usize>,
    epochs: Vec<Epoch>,
    valid_for_seconds: Option<u64>,
    prepared_at: chrono::DateTime<chrono::Utc>,
    failed: bool,
    closed_expiry: Vec<closed_expiry::Lifetime>,
}

#[derive(Debug, Clone)]
pub(super) struct Prepared {
    profile: usize,
    epoch: usize,
    token: Uuid,
    target_event_index: Option<usize>,
    target_key_fingerprint: String,
    initial_expiry: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct ObservationAudit {
    rule_id: String,
    case_id: String,
    kind: Kind,
    source_key_fingerprint: String,
    target_key_fingerprint: String,
    target_event_index: Option<usize>,
    source_witness: super::super::report::command::CommandExchangeRefReport,
    source_epoch_mutation: Option<super::super::report::command::CommandExchangeRefReport>,
    covered_source_observations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage: Option<closed_expiry::Coverage>,
}

#[derive(Debug, Default)]
pub(super) struct Observations {
    prepared: BTreeSet<String>,
    profiles: Vec<Profile>,
    owners: BTreeMap<usize, (usize, usize)>,
    calls: BTreeMap<String, usize>,
    in_flight: BTreeMap<Uuid, usize>,
    mutations_at: BTreeMap<usize, chrono::DateTime<chrono::Utc>>,
    initial_expiry_at: BTreeMap<usize, chrono::DateTime<chrono::Utc>>,
    expiry_by_exchange: BTreeMap<usize, Vec<(usize, usize)>>,
    audits: Vec<ObservationAudit>,
    omitted: usize,
}

impl Observations {
    pub(super) fn in_flight_diagnostic(&self) -> serde_json::Value {
        let cases = self
            .in_flight
            .values()
            .take(4)
            .map(|&profile| self.profiles[profile].case.as_str())
            .collect::<Vec<_>>();
        serde_json::json!({"count":self.in_flight.len(), "cases":cases,
            "omitted":self.in_flight.len().saturating_sub(4)})
    }

    pub(super) fn has_in_flight(&self) -> bool {
        !self.in_flight.is_empty()
    }
    pub(super) fn reports(&self) -> Vec<ObservationAudit> {
        self.audits.clone()
    }
    pub(super) fn omitted(&self) -> usize {
        self.omitted
    }
    pub(super) fn native_rule(&self, index: usize) -> Option<&str> {
        self.owners.get(&index).and_then(|&(p, _)| {
            let profile = &self.profiles[p];
            matches!(profile.kind, Kind::Expiry | Kind::AbsentRead).then_some(profile.rule.as_str())
        })
    }
    pub(super) fn check_case_addition(
        &self,
        source: ReplaySource,
        case: Option<&str>,
    ) -> Result<()> {
        ensure!(
            source != ReplaySource::Case || !case.is_some_and(|case| self.prepared.contains(case)),
            "cannot extend prepared state-observation Case inventory"
        );
        Ok(())
    }
    pub(super) fn check_inventory_addition(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
        source: ReplaySource,
        case: Option<&str>,
        reusable_snapshot: bool,
    ) -> Result<()> {
        ensure!(
            !self.profiles.iter().any(|p| record.database == p.database
                && target_matches(&p.target, &record.target_host, record.target_port)
                && super::key_access::touches(&record.command, args, &p.key)
                && (reusable_snapshot
                    || !super::case_scope::is_other_ordinary_case(&p.case, source, case, record))),
            "cannot add Global or explicitly shared key inventory after Case state preparation"
        );
        Ok(())
    }
}

fn selected(effect: &NativeEffect) -> bool {
    matches!(
        effect,
        NativeEffect::RedisExpiryRefresh(_) | NativeEffect::RedisReadObservation
    ) || effect
        .redis_read_back()
        .iter()
        .any(|r| r.contract.state_epochs)
}

impl RedisReplayState {
    pub(super) fn prepare_observations(&mut self, case: &str) -> Result<()> {
        if self.observations.prepared.contains(case) {
            return Ok(());
        }
        let mut profiles = Vec::new();
        let mut seen = BTreeSet::new();
        for seed in self
            .exchanges
            .iter()
            .filter(|e| e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case))
        {
            for compiled in self
                .request_contracts
                .compiled_rules()
                .into_iter()
                .flat_map(|p| &p.native)
            {
                let rule = &compiled.rule;
                let kind = if matches!(rule.effect, NativeEffect::RedisExpiryRefresh(_))
                    && (seed.record.command == "EXPIRE"
                        || seed.record.command == "SET" && seed.args.len() == 4)
                {
                    Kind::Expiry
                } else if seed.record.command == "GET"
                    && matches!(rule.effect, NativeEffect::RedisReadObservation)
                {
                    Kind::AbsentRead
                } else if seed.record.command == "GET"
                    && rule
                        .effect
                        .redis_read_back()
                        .iter()
                        .any(|e| e.contract.state_epochs)
                {
                    Kind::Read
                } else {
                    continue;
                };
                let target = TargetKey {
                    host: seed.record.target_host.clone(),
                    port: seed.record.target_port,
                };
                if !self.request_contracts.native_rule_scope_matches(
                    &rule.id,
                    Some(case),
                    Protocol::Redis,
                    &target,
                    Some(&Database::Index(seed.record.database)),
                    seed.record.username.as_deref(),
                ) || !rule.selector.key.as_ref().is_some_and(|k| {
                    seed.args.first().is_some_and(|key| {
                        crate::replay::policy::native_projection::key(k).matches(key)
                    })
                }) {
                    continue;
                }
                let partition = (
                    target,
                    seed.record.database,
                    normalize_optional(seed.record.username.as_deref()),
                    seed.record.resp_version,
                    seed.args[0].clone(),
                    kind as u8,
                );
                if !seen.insert(partition.clone()) {
                    continue;
                }
                if kind == Kind::Read && !source::has_owned_set(self, case, seed)? {
                    continue;
                }
                let prepared = source::prepare(self, case, &rule.id, kind, seed);
                // A SET without a complete closed-scalar proof grants nothing.
                // Any actual Source EXPIRE still requires its existing full proof.
                if seed.record.command == "SET" && kind == Kind::Expiry && prepared.is_err() {
                    seen.remove(&partition);
                    continue;
                }
                if let Some(profile) = prepared.with_context(|| {
                    format!(
                        "state observation rule={} key_fingerprint={} case={case}",
                        rule.id,
                        fingerprint(&seed.args[0]),
                    )
                })? {
                    ensure!(
                        profiles.len() < MAX_KEYS,
                        "state observations exceed Case key limit"
                    );
                    profiles.push(profile);
                }
            }
        }
        ensure!(
            profiles
                .iter()
                .map(|p| {
                    let finite = if p.kind == Kind::Expiry {
                        p.initial_accesses.len()
                    } else {
                        p.finite_prefix.len()
                    };
                    finite + p.epochs.iter().map(|e| e.observations.len()).sum::<usize>()
                })
                .sum::<usize>()
                <= MAX_OBSERVATIONS,
            "state observations exceed Case Source observation limit"
        );
        ensure!(
            profiles
                .iter()
                .flat_map(|p| &p.epochs)
                .flat_map(|e| &e.observations)
                .all(|&i| self.exchanges[i].read_commutation_rule.is_none()
                    && self.exchanges[i].observation_rule.is_none()),
            "state observations overlap another observation owner"
        );
        // All Source proofs must succeed before any lane permission is installed.
        for profile in profiles {
            let owner = self.observations.profiles.len();
            self.observations.index_closed_expiry(owner, &profile);
            for (epoch, entry) in profile.epochs.iter().enumerate() {
                for &index in &entry.observations {
                    self.exchanges[index].observation_rule = Some(profile.rule.clone());
                    self.observations.owners.insert(index, (owner, epoch));
                }
            }
            self.observations.profiles.push(profile);
        }
        self.observations.prepared.insert(case.into());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observation_candidate(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) -> std::result::Result<Option<usize>, CommandMatchDiagnostic> {
        let mut selected = None;
        for (profile_index, profile) in self.observations.profiles.iter().enumerate() {
            if Some(profile.case.as_str()) != case
                || profile.database != database
                || profile.resp_version != resp_version
                || normalize_optional(profile.username.as_deref()) != normalize_optional(username)
                || !target_matches(target, &profile.target.host, profile.target.port)
                || command
                    != if profile.kind.is_read() {
                        "GET"
                    } else {
                        "EXPIRE"
                    }
            {
                continue;
            }
            let Some(representative) = profile
                .epochs
                .iter()
                .flat_map(|e| &e.observations)
                .next()
                .copied()
            else {
                continue;
            };
            let representative = &self.exchanges[representative];
            let mut key_arguments = args.to_vec();
            if profile.kind == Kind::Expiry && key_arguments.len() == 2 {
                key_arguments[1] = representative.args[1].clone();
            }
            if !self
                .connection_scopes
                .matches(representative, case, connection)
                || !self.arguments_match(representative, &key_arguments)
            {
                continue;
            }
            let epoch = profile
                .epochs
                .iter()
                .rev()
                .find(|epoch| {
                    epoch.mutation.is_none_or(|i| {
                        matches!(
                            self.exchanges[i].status,
                            ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Responding
                        )
                    })
                })
                .expect("every Source profile has an initial epoch");
            let reject = |reason: &str| self.observation_mismatch(profile, epoch, reason);
            if profile.kind == Kind::AbsentRead
                && epoch
                    .mutation
                    .is_some_and(|index| !self.exchanges[index].status.is_consumed())
            {
                return Err(reject("absent-state deletion has not completed delivery"));
            }
            if profile.kind == Kind::Expiry
                && epoch.mutation.is_none()
                && profile
                    .finite_prefix
                    .iter()
                    .any(|&index| !self.exchanges[index].status.is_consumed())
            {
                return Err(reject(
                    "finite Source accesses must finish before the initial existing-key refresh",
                ));
            }
            if profile.kind != Kind::Expiry
                && epoch.mutation.is_none()
                && !profile.finite_prefix.is_empty()
            {
                let prefix = profile
                    .finite_prefix
                    .iter()
                    .map(|&index| {
                        let record = &self.exchanges[index].record;
                        (record.connection_id, record.sequence)
                    })
                    .collect::<BTreeSet<_>>();
                let candidate = crate::replay::command_matching::preferred_match(
                    &self.exchanges,
                    case,
                    |exchange| {
                        prefix.contains(&(exchange.record.connection_id, exchange.record.sequence))
                            && exchange.status.is_available()
                            && self.connection_scopes.matches(exchange, case, connection)
                            && self.arguments_match(exchange, args)
                    },
                );
                let candidate = match candidate {
                    crate::replay::command_matching::PreferredMatch::Matched(index) => index,
                    crate::replay::command_matching::PreferredMatch::LaneBlocked {
                        candidate,
                        blocker,
                    } => {
                        return Err(crate::replay::command_matching::lane_blocked_diagnostic(
                            &self.exchanges,
                            candidate,
                            blocker,
                        ));
                    }
                    crate::replay::command_matching::PreferredMatch::NotFound => {
                        return Err(reject(
                            "unknown initial state has no remaining finite Source read; a proven mutation must establish the next epoch",
                        ));
                    }
                };
                if selected.is_some() {
                    return Err(reject("Source state-observation ownership is ambiguous"));
                }
                selected = Some(candidate);
                continue;
            }
            if profile
                .epochs
                .iter()
                .filter_map(|e| e.mutation)
                .any(|i| self.exchanges[i].status == ReplayExchangeStatus::Failed)
            {
                return Err(reject(
                    "an earlier key mutation failed delivery; current state is not proven",
                ));
            }
            let Some(&index) = epoch.observations.first() else {
                return Err(reject(
                    "current key state has no Source observation witness; cannot borrow a future lifetime",
                ));
            };
            if !self.arguments_match(&self.exchanges[index], args) {
                return Err(reject(
                    "TTL arguments differ from the proven Source refresh",
                ));
            }
            if profile.failed {
                return Err(reject("an earlier observation delivery failed"));
            }
            let established_at = match epoch.mutation {
                Some(index) => Some(
                    self.observations
                        .mutations_at
                        .get(&index)
                        .copied()
                        .unwrap_or(profile.prepared_at),
                ),
                None if profile.kind == Kind::Expiry => self
                    .observations
                    .initial_expiry_at
                    .get(&profile_index)
                    .copied(),
                None => None,
            };
            let expirable = epoch.mutation.map_or(profile.kind == Kind::Expiry, |i| {
                !matches!(self.exchanges[i].record.command.as_str(), "DEL" | "UNLINK")
            });
            if expirable
                && established_at.is_some_and(|established_at| {
                    !profile.valid_for_seconds.is_none_or(|seconds| {
                        chrono::Utc::now()
                            .signed_duration_since(established_at)
                            .num_milliseconds()
                            < i64::try_from(seconds.saturating_mul(1000)).unwrap_or(i64::MAX)
                    })
                })
            {
                return Err(reject("key lifetime exceeds its proven positive TTL"));
            }
            if self
                .observations
                .calls
                .get(&profile.case)
                .copied()
                .unwrap_or(0)
                >= MAX_CALLS
            {
                return Err(reject("Target state-observation call limit exceeded"));
            }
            if selected.is_some() {
                return Err(reject("Source state-observation ownership is ambiguous"));
            }
            selected = Some(index);
        }
        Ok(selected)
    }

    fn observation_mismatch(
        &self,
        profile: &Profile,
        epoch: &Epoch,
        reason: &str,
    ) -> CommandMatchDiagnostic {
        CommandMatchDiagnostic::RedisStateObservationMismatch {
            rule_id: profile.rule.clone(),
            source_key_fingerprint: fingerprint(&profile.key),
            source_epoch_mutation: epoch.mutation.map(|i| {
                let e = &self.exchanges[i];
                Box::new(super::super::report::command::CommandExchangeRefReport {
                    case_id: e.case_id.clone(),
                    source: e.source,
                    connection_id: e.record.connection_id,
                    sequence: e.record.sequence,
                    command: e.record.command.clone(),
                })
            }),
            reason: reason.into(),
        }
    }

    pub(super) fn check_observation_mutation(
        &self,
        index: usize,
    ) -> std::result::Result<(), CommandMatchDiagnostic> {
        for profile in &self.observations.profiles {
            // Pooled request order follows claims; delivery completion is tracked separately.
            if let Some(position) = profile.initial_accesses.iter().position(|&i| i == index)
                && profile.initial_accesses[..position]
                    .iter()
                    .any(|&i| !self.exchanges[i].satisfies_lane_order())
            {
                return Err(self.observation_mismatch(
                    profile,
                    &profile.epochs[0],
                    "finite initial existing-key accesses must be claimed in Source order",
                ));
            }
            let Some(position) = profile
                .epochs
                .iter()
                .position(|e| e.mutation == Some(index))
            else {
                continue;
            };
            if position == 1
                && profile
                    .finite_prefix
                    .iter()
                    .any(|&index| !self.exchanges[index].status.is_consumed())
            {
                return Err(self.observation_mismatch(
                    profile,
                    &profile.epochs[position],
                    "finite Source reads of unknown initial state must finish before the first mutation",
                ));
            }
            if let Some(blocker) = profile.epochs[..position].iter().find(|e| {
                e.mutation.is_some_and(|i| {
                    !matches!(
                        self.exchanges[i].status,
                        ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Responding
                    )
                })
            }) {
                return Err(self.observation_mismatch(
                    profile,
                    blocker,
                    "an earlier Source mutation of this key is still unclaimed",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn record_observation_mutation(&mut self, index: usize, args: &[Vec<u8>]) {
        self.reserve_closed_expiry(index, args);
        if self
            .observations
            .profiles
            .iter()
            .any(|p| p.epochs.iter().any(|e| e.mutation == Some(index)))
        {
            self.observations
                .mutations_at
                .entry(index)
                .or_insert_with(chrono::Utc::now);
        }
    }

    pub(super) fn reserve_observation(
        &mut self,
        index: usize,
        args: &[Vec<u8>],
    ) -> Option<Prepared> {
        let &(profile, epoch) = self.observations.owners.get(&index)?;
        if self.observations.profiles[profile].kind == Kind::Expiry
            && self.observations.profiles[profile].epochs[epoch]
                .mutation
                .is_none()
        {
            self.observations
                .initial_expiry_at
                .entry(profile)
                .or_insert_with(chrono::Utc::now);
        }
        let case = &self.observations.profiles[profile].case;
        let prepared = Prepared {
            profile,
            epoch,
            token: Uuid::new_v4(),
            target_event_index: self.request_event_index,
            target_key_fingerprint: fingerprint(args.first()?),
            initial_expiry: None,
        };
        *self.observations.calls.entry(case.clone()).or_default() += 1;
        self.observations.in_flight.insert(prepared.token, profile);
        Some(prepared)
    }

    pub(super) fn complete_observation(&mut self, prepared: &Prepared, witness: usize) {
        if self
            .observations
            .in_flight
            .remove(&prepared.token)
            .is_none()
        {
            return;
        }
        let profile = &self.observations.profiles[prepared.profile];
        let epoch = &profile.epochs[prepared.epoch];
        let covered = epoch
            .observations
            .iter()
            .filter(|&&i| !self.exchanges[i].status.is_consumed())
            .count();
        let reference = |index: usize| {
            let e = &self.exchanges[index];
            super::super::report::command::CommandExchangeRefReport {
                case_id: e.case_id.clone(),
                source: e.source,
                connection_id: e.record.connection_id,
                sequence: e.record.sequence,
                command: e.record.command.clone(),
            }
        };
        let audit = ObservationAudit {
            rule_id: profile.rule.clone(),
            case_id: profile.case.clone(),
            kind: profile.kind,
            source_key_fingerprint: fingerprint(&profile.key),
            target_key_fingerprint: prepared.target_key_fingerprint.clone(),
            target_event_index: prepared.target_event_index,
            source_witness: reference(witness),
            source_epoch_mutation: epoch.mutation.map(reference),
            covered_source_observations: covered,
            coverage: prepared
                .initial_expiry
                .map(|lifetime| profile.closed_expiry[lifetime].refresh_coverage(self)),
        };
        for &index in &epoch.observations {
            let exchange = &mut self.exchanges[index];
            exchange.status = ReplayExchangeStatus::Consumed;
            exchange.matched_once = true;
        }
        if self.observations.audits.len() < 1000 {
            self.observations.audits.push(audit);
        } else {
            self.observations.omitted += 1;
        }
    }

    pub(super) fn fail_observation(&mut self, prepared: &Prepared) {
        self.observations.in_flight.remove(&prepared.token);
        self.observations.profiles[prepared.profile].failed = true;
    }
}

pub(in crate::replay) fn validate_source(
    contracts: &crate::replay::policy::request_contract::RequestContracts,
    cases: &[crate::replay::policy::native_projection::NativeSourceCase<'_>],
) -> Result<BTreeMap<String, usize>> {
    let mut state = super::native_source::source_inventory(contracts, cases, selected)?;
    for case in cases {
        state.prepare_observations(case.id)?;
    }
    let mut counts = BTreeMap::new();
    for profile in &state.observations.profiles {
        *counts.entry(profile.rule.clone()).or_default() += profile
            .epochs
            .iter()
            .map(|e| e.observations.len())
            .sum::<usize>()
            + profile
                .closed_expiry
                .iter()
                .filter(|l| profile.epochs[l.epoch].observations.is_empty())
                .count();
    }
    Ok(counts)
}

fn fingerprint(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
