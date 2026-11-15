//! Explicit case-local APPEND byte streams. Observations and other commands stay finite.
use super::*;
use crate::policy::{Database, NativeEffect, Protocol};
use crate::protocols::replay::redis::report::CommandMatchDiagnostic;
use crate::protocols::replay::redis::report::RedisDiagnostic;
use serde::Serialize;

pub(crate) mod cancelled;
mod diagnostic;
pub(crate) use diagnostic::{AppendBoundaryMismatch, AppendMismatch};
mod source;
mod trace;
pub(crate) use source::validate_source;
#[cfg(test)]
mod case_scope_tests;
#[cfg(test)]
mod identity_key_tests;
#[cfg(test)]
mod key_scope_tests;
#[cfg(test)]
mod recorded_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
pub(super) mod tests;

const MAX_BYTES: usize = crate::value_limits::MAX_VALUE_BYTES;
const MAX_VALUE: usize = crate::value_limits::MAX_VALUE_BYTES;
const MAX_PIECES: usize = 4096;
const MAX_STREAMS: usize = 128;
const MAX_FRAGMENTS: usize = 64;
const MAX_CALLS: usize = 4096;

#[derive(Debug, Default)]
pub(super) struct AppendStreams {
    prepared: BTreeSet<String>,
    profiles: Vec<Profile>,
    owners: BTreeMap<usize, (usize, usize)>,
    calls: BTreeMap<String, usize>,
    audits: Vec<AppendAudit>,
    omitted_audits: usize,
}

#[derive(Debug)]
struct Profile {
    rule: String,
    case: String,
    target: TargetKey,
    database: i64,
    username: Option<String>,
    resp_version: u8,
    key: Vec<u8>,
    bytes: Vec<u8>,
    pieces: Vec<Piece>,
    barriers: Vec<(usize, usize)>,
    target_key: Option<Vec<u8>>,
    reserved: usize,
    delivered: usize,
    completed: BTreeMap<usize, usize>,
    in_flight: BTreeMap<usize, usize>,
    failed: bool,
    cancelled_cache: Option<cancelled::Cache>,
}

#[derive(Debug)]
struct Piece {
    index: usize,
    start: usize,
    end: usize,
    epoch_start: usize,
    base: usize,
}

#[derive(Debug, Clone)]
pub(super) struct PreparedAppend {
    profile: usize,
    from: usize,
    to: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AppendFragment {
    source_connection: Uuid,
    source_sequence: u64,
    source_offset: usize,
    target_offset: usize,
    bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AppendAudit {
    rule_id: String,
    case_id: String,
    target_observation: Option<Uuid>,
    source_key_fingerprint: String,
    target_key_fingerprint: String,
    payload_fingerprint: String,
    from: usize,
    to: usize,
    returned_length: usize,
    fragments: Vec<AppendFragment>,
}

impl AppendStreams {
    pub(super) fn reports(&self) -> Vec<AppendAudit> {
        self.audits.clone()
    }
    pub(super) fn omitted(&self) -> usize {
        self.omitted_audits
    }
    pub(super) fn idle_source(&self, index: usize) -> bool {
        let Some((profile, piece)) = self.owners.get(&index) else {
            return false;
        };
        let profile = &self.profiles[*profile];
        let piece = &profile.pieces[*piece];
        !profile
            .in_flight
            .iter()
            .any(|(from, to)| *from < piece.end && piece.start < *to)
    }
    pub(super) fn has_case(&self, case: &str) -> bool {
        self.profiles.iter().any(|p| p.case == case)
    }
    pub(super) fn check_inventory_addition(
        &self,
        record: &RecordedExchange,
        args: &[Vec<u8>],
        source: ReplaySource,
        case_id: Option<&str>,
    ) -> Result<()> {
        ensure!(
            !self.profiles.iter().any(|profile| {
                !super::case_scope::is_other_ordinary_case(&profile.case, source, case_id, record)
                    && record.native.database == profile.database
                    && target_matches(
                        &profile.target,
                        &record.native.target_host,
                        record.native.target_port,
                    )
                    && super::key_access::touches(&record.native.command, args, &profile.key)
            }),
            "cannot add overlapping inventory after append stream Source preparation"
        );
        Ok(())
    }
}

impl RedisReplayState {
    pub(crate) fn append_stream_owns(&self, index: usize) -> bool {
        self.append_streams.owners.contains_key(&index)
    }

    /// Prepare a complete immutable Case once, before any selected write can claim bytes.
    pub(crate) fn prepare_append_case(&mut self, case: &str) -> Result<()> {
        if self.append_streams.prepared.contains(case) {
            return Ok(());
        }
        let mut profiles = Vec::new();
        let mut keys = BTreeSet::new();
        for exchange in &self.exchanges {
            if exchange.source != ReplaySource::Case
                || exchange.case_id.as_deref() != Some(case)
                || exchange.record.native.command != "APPEND"
            {
                continue;
            }
            let target = TargetKey {
                host: exchange.record.native.target_host.clone(),
                port: exchange.record.native.target_port,
            };
            for rule in self
                .request_contracts
                .compiled_rules()
                .into_iter()
                .flat_map(|p| &p.native)
            {
                if !matches!(rule.rule.effect, NativeEffect::RedisAppendStream)
                    || !self.request_contracts.native_rule_scope_matches(
                        &rule.rule.id,
                        Some(case),
                        Protocol::Redis,
                        &target,
                        Some(&Database::Index(exchange.record.native.database)),
                        exchange.record.native.username.as_deref(),
                    )
                    || !rule.rule.selector.key.as_ref().is_some_and(|selector| {
                        exchange.args.first().is_some_and(|key| {
                            crate::policy::runtime::native_projection::key(selector).matches(key)
                        })
                    })
                {
                    continue;
                }
                let identity = (
                    target.clone(),
                    exchange.record.native.database,
                    exchange.record.native.username.clone(),
                    exchange.args[0].clone(),
                );
                if !keys.insert(identity) {
                    continue;
                }
                ensure!(
                    profiles.len() < MAX_STREAMS,
                    "append stream exceeds Case key limit"
                );
                profiles.push(trace::prepare(
                    &self.exchanges,
                    case,
                    &rule.rule.id,
                    exchange,
                )?);
            }
        }
        ensure!(
            profiles.iter().map(|p| p.bytes.len()).sum::<usize>() <= MAX_BYTES,
            "append stream exceeds Case byte limit"
        );
        for profile in profiles {
            let owner = self.append_streams.profiles.len();
            for (piece_index, piece) in profile.pieces.iter().enumerate() {
                self.append_streams
                    .owners
                    .insert(piece.index, (owner, piece_index));
            }
            self.append_streams.profiles.push(profile);
        }
        self.append_streams.prepared.insert(case.into());
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // Native protocol identity stays explicit.
    pub(super) fn match_append(
        &mut self,
        case: &str,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        args: &[Vec<u8>],
    ) -> Result<Option<MatchedRedisExchange>> {
        if args.len() != 2 {
            return Ok(None);
        }
        let mut selected = None;
        for (profile_index, profile) in self.append_streams.profiles.iter().enumerate() {
            if profile.case != case
                || profile.database != database
                || normalize_optional(username) != normalize_optional(profile.username.as_deref())
                || profile.resp_version != resp_version
                || !target_matches(target, &profile.target.host, profile.target.port)
            {
                continue;
            }
            let representative = profile
                .pieces
                .first()
                .context("append stream has no Source write")?;
            let exchange = &self.exchanges[representative.index];
            // Existing capture/reference rules may translate the key. Text is
            // deliberately absent from this comparison and is checked bytewise below.
            let mut source = vec![profile.key.clone(), Vec::new()];
            let mut actual = vec![args[0].clone(), Vec::new()];
            let normalized = self
                .dynamic_values
                .redis_with_identity(
                    Some(case),
                    target,
                    crate::policy::runtime::dynamic_values::RedisIdentity { database, username },
                    "APPEND",
                    &source,
                    &actual,
                )
                .transpose();
            let Ok(normalized) = normalized else {
                continue;
            };
            if let Some(normalized) = normalized {
                source = normalized.source;
                actual = normalized.actual;
            }
            // JSON metadata can establish the complete content-key identity
            // before the write. Consume the same accepted relation as ordinary
            // Redis matching; this projection cannot create a new identity.
            if let Some(projected) = self
                .request_contracts
                .project_known_redis_keys(case, "APPEND", &source, &actual)?
            {
                actual = projected;
            }
            if source[0] != actual[0] {
                continue;
            }
            ensure!(
                selected.is_none(),
                "append stream key ownership is ambiguous"
            );
            ensure!(!profile.failed, "append stream has a failed delivery");
            ensure!(
                profile
                    .target_key
                    .as_ref()
                    .is_none_or(|key| key == &args[0]),
                "append stream changed its Target key"
            );
            ensure!(
                exchange.shared_rule_id.is_none(),
                "shared APPEND cannot use a stream rule"
            );
            selected = Some(profile_index);
        }
        let Some(profile_index) = selected else {
            return Ok(None);
        };
        let profile = &self.append_streams.profiles[profile_index];
        ensure!(
            !args[1].is_empty() && args[1].len() <= MAX_VALUE,
            "append stream chunk size is unsupported"
        );
        let from = profile.reserved;
        let to = from
            .checked_add(args[1].len())
            .context("append stream offset overflow")?;
        if profile.bytes.get(from..to) != Some(args[1].as_slice()) {
            return Err(diagnostic::bytes_mismatch(
                profile,
                &self.exchanges,
                &args[1],
                self.request_observation_id,
            )
            .into());
        }
        for (index, offset) in &profile.barriers {
            if *offset < to {
                ensure!(
                    satisfies(&self.exchanges[*index]),
                    "append stream cannot cross an unclaimed observation or mutation barrier"
                );
            }
        }
        let pieces = profile
            .pieces
            .iter()
            .filter(|p| p.start < to && from < p.end)
            .collect::<Vec<_>>();
        ensure!(
            (!pieces.is_empty() || profile.cancelled_cache.is_some())
                && pieces.len() <= MAX_FRAGMENTS,
            "append stream fragment limit exceeded"
        );
        let epoch = pieces
            .first()
            .copied()
            .unwrap_or_else(|| profile.pieces.last().unwrap());
        ensure!(
            pieces
                .iter()
                .all(|p| p.epoch_start == epoch.epoch_start && p.base == epoch.base),
            "append stream cannot merge across a reset"
        );
        for piece in &pieces {
            let exchange = &self.exchanges[piece.index];
            ensure!(
                self.connection_scopes
                    .matches(exchange, Some(case), connection),
                "append stream connection scope differs"
            );
            ensure!(
                matches!(
                    exchange.status,
                    ReplayExchangeStatus::Available | ReplayExchangeStatus::Responding
                ),
                "append stream Source exchange is unavailable"
            );
        }
        let bound_lanes = pieces
            .iter()
            .filter_map(|piece| {
                let exchange = &self.exchanges[piece.index];
                (!exchange.connection_independent && self.connection_scopes.is_stateful(exchange))
                    .then_some(exchange.record.native.connection_id)
            })
            .collect::<BTreeSet<_>>();
        ensure!(
            bound_lanes.is_empty()
                || (bound_lanes.len() == 1
                    && pieces.iter().all(|piece| {
                        bound_lanes
                            .contains(&self.exchanges[piece.index].record.native.connection_id)
                    })),
            "append stream cannot merge different stateful connection scopes"
        );
        ensure!(
            self.append_streams.calls.get(case).copied().unwrap_or(0) < MAX_CALLS,
            "append stream Target call limit exceeded"
        );
        let returned = epoch
            .base
            .checked_add(to - epoch.epoch_start)
            .context("append stream length overflow")?;
        let index = epoch.index;
        ensure!(
            self.connection_scopes
                .matches(&self.exchanges[index], Some(case), connection),
            "append stream connection scope differs"
        );
        let fragments = pieces
            .iter()
            .map(|piece| {
                let begin = from.max(piece.start);
                let end = to.min(piece.end);
                let exchange = &self.exchanges[piece.index];
                AppendFragment {
                    source_connection: exchange.record.native.connection_id,
                    source_sequence: exchange.record.native.sequence,
                    source_offset: begin - piece.start,
                    target_offset: begin - from,
                    bytes: end - begin,
                }
            })
            .collect();
        let delay = pieces
            .iter()
            .filter(|p| self.exchanges[p.index].status == ReplayExchangeStatus::Available)
            .try_fold(0_u64, |sum, p| {
                sum.checked_add(self.exchanges[p.index].record.native.duration_ms)
                    .context("append stream duration overflow")
            })?;
        let audit = AppendAudit {
            rule_id: profile.rule.clone(),
            case_id: case.into(),
            target_observation: self.request_observation_id,
            source_key_fingerprint: crate::policy_evidence::digest(&profile.key),
            target_key_fingerprint: crate::policy_evidence::digest(&args[0]),
            payload_fingerprint: crate::policy_evidence::digest(&args[1]),
            from,
            to,
            returned_length: returned,
            fragments,
        };
        let rule_id = profile.rule.clone();
        let indices = pieces.iter().map(|p| p.index).collect::<Vec<_>>();
        for &index in &indices {
            self.record_observation_mutation(index, args);
        }
        let profile = &mut self.append_streams.profiles[profile_index];
        profile.reserved = to;
        profile.in_flight.insert(from, to);
        profile.target_key = Some(args[0].clone());
        let mut requires_binding = false;
        for index in indices {
            requires_binding |=
                self.connection_scopes
                    .bind(&self.exchanges[index], Some(case), connection);
            self.exchanges[index].status = ReplayExchangeStatus::Responding;
        }
        *self.append_streams.calls.entry(case.into()).or_default() += 1;
        if self.append_streams.audits.len() < 1000 {
            self.append_streams.audits.push(audit);
        } else {
            self.append_streams.omitted_audits += 1;
        }
        let exchange = &self.exchanges[index];
        Ok(Some(MatchedRedisExchange {
            claim: Claim::Native(NativeClaimKind::AppendStream),
            refresh: None,
            observation: None,
            append: Some(PreparedAppend {
                profile: profile_index,
                from,
                to,
            }),
            read_back: None,
            time_read: None,
            time_write: None,
            unified_delivery: None,
            rpc_push: None,
            rpc_response: None,
            adapter_echo: None,
            publish_duration_ms: 0,
            index,
            connection_id: exchange.record.native.connection_id,
            response: format!(":{returned}\r\n").into_bytes(),
            timing: ReplayExchangeTiming::from_recorded(delay, DependencyExchangeOutcome::Response),
            requires_binding,
            rule_ids: vec![rule_id],
            report: CommandMatchedReport {
                case_id: Some(case.into()),
                source: ReplaySource::Case,
                index,
                target: target.clone(),
                connection_id: exchange.record.native.connection_id,
                sequence: exchange.record.native.sequence,
                command: "APPEND".into(),
                shared_origin: None,
                target_event_index: None,
            },
        }))
    }

    pub(super) fn check_append_barrier(&self, index: usize, args: &[Vec<u8>]) -> Result<()> {
        ensure!(
            !self.append_streams.owners.contains_key(&index),
            "APPEND must use its validated Source byte stream; ordinary matching cannot claim it"
        );
        for profile in &self.append_streams.profiles {
            if let Some((_, offset)) = profile.barriers.iter().find(|(i, _)| *i == index) {
                ensure!(
                    !profile.failed,
                    "append stream disabled by an earlier delivery failure"
                );
                if profile.reserved != *offset {
                    return Err(diagnostic::boundary_mismatch(
                        profile,
                        &self.exchanges[index],
                        *offset,
                    )
                    .into());
                }
                if matches!(
                    self.exchanges[index].record.native.command.as_str(),
                    "SET" | "SETEX" | "PSETEX"
                ) {
                    ensure!(
                        self.exchanges[index].args.get(1..) == args.get(1..),
                        "append stream reset value/options must remain byte exact"
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn complete_append(&mut self, prepared: &PreparedAppend) -> Vec<usize> {
        let profile = &mut self.append_streams.profiles[prepared.profile];
        let previous_delivered = profile.delivered;
        profile.in_flight.remove(&prepared.from);
        profile.completed.insert(prepared.from, prepared.to);
        while let Some(end) = profile.completed.remove(&profile.delivered) {
            profile.delivered = end;
        }
        let mut indices = Vec::new();
        for piece in &profile.pieces {
            if piece.end <= profile.delivered {
                self.exchanges[piece.index].status = ReplayExchangeStatus::Consumed;
                self.exchanges[piece.index].matched_once = true;
                if previous_delivered < piece.end {
                    indices.push(piece.index);
                }
            }
        }
        if profile.delivered == profile.bytes.len() && profile.cancelled_cache.is_none() {
            profile.bytes = Vec::new();
        }
        indices
    }

    pub(super) fn fail_append(&mut self, prepared: &PreparedAppend) {
        let profile = &mut self.append_streams.profiles[prepared.profile];
        profile.in_flight.remove(&prepared.from);
        profile.failed = true;
        for piece in &profile.pieces {
            if piece.start < prepared.to && prepared.from < piece.end {
                self.exchanges[piece.index].status = ReplayExchangeStatus::Failed;
            }
        }
    }
}

fn satisfies(exchange: &ReplayExchange) -> bool {
    exchange.status.is_consumed() || exchange.status == ReplayExchangeStatus::Responding
}

pub(super) fn diagnostic(error: anyhow::Error) -> CommandMatchDiagnostic {
    if let Some(mismatch) = error.downcast_ref::<AppendBoundaryMismatch>() {
        return CommandMatchDiagnostic::Native(RedisDiagnostic::AppendStreamBoundary {
            details: Box::new(mismatch.clone()),
        });
    }
    if let Some(mismatch) = error.downcast_ref::<AppendMismatch>() {
        return CommandMatchDiagnostic::Native(RedisDiagnostic::AppendStream {
            details: Box::new(mismatch.clone()),
        });
    }
    CommandMatchDiagnostic::EvidenceUnavailable {
        reason: format!("append stream rejected: {error:#}"),
    }
}
