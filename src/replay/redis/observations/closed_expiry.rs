//! A delivered TTL-bearing SET can make refreshes redundant until a delivered DEL.
//! This never makes the creation, reads, deletion or content work optional.
use super::*;
use crate::replay::report::command::CommandExchangeRefReport;
use std::time::Duration;
use tokio::time::Instant;
mod refresh;

#[cfg(test)]
mod recorded_tests;
#[cfg(test)]
mod tcp_tests;
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) struct Lifetime {
    pub(super) epoch: usize,
    creation: usize,
    deletion: usize,
    required: Vec<usize>,
    ttl: Duration,
    established: Option<Instant>,
    closed: Option<Instant>,
    creation_key: Option<String>,
    deletion_key: Option<String>,
    deletion_event: Option<usize>,
    failed: bool,
    settled: bool,
    used_refresh: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Coverage {
    InitialExpiryUntilDelete {
        source_deletion: CommandExchangeRefReport,
        ttl_seconds: u64,
        target_lifetime_ms: u128,
    },
    InitialExpiryRefresh {
        source_deletion: CommandExchangeRefReport,
        ttl_seconds: u64,
        target_lifetime_ms: u128,
    },
}

pub(super) fn prove(state: &RedisReplayState, profile: &Profile, trace: &[usize]) -> Vec<Lifetime> {
    if trace.len() > MAX_OBSERVATIONS {
        return vec![];
    }
    let positions = trace
        .iter()
        .enumerate()
        .map(|(p, &i)| (i, p))
        .collect::<BTreeMap<_, _>>();
    profile
        .epochs
        .windows(2)
        .enumerate()
        .filter_map(|(epoch, pair)| {
            let (creation, deletion) = pair[0].mutation.zip(pair[1].mutation)?;
            let first = &state.exchanges[creation];
            let last = &state.exchanges[deletion];
            // Multi-key DEL's aggregate count cannot prove this particular key existed.
            if first.record.command != "SET"
                || first.args.len() != 4
                || !matches!(last.record.command.as_str(), "DEL" | "UNLINK")
                || last.args != [profile.key.clone()]
                || last.response_bytes().ok()? != b":1\r\n"
            {
                return None;
            }
            let ttl = set_ttl(&first.args)?;
            let elapsed = last
                .record
                .timestamp?
                .signed_duration_since(first.record.earliest_start()?)
                .to_std()
                .ok()?;
            if elapsed >= ttl {
                return None;
            }
            let start = *positions.get(&creation)?;
            let end = *positions.get(&deletion)?;
            if end < start || end - start >= MAX_OBSERVATIONS {
                return None;
            }
            let mut expected = format!("${}\r\n", first.args[1].len()).into_bytes();
            expected.extend_from_slice(&first.args[1]);
            expected.extend_from_slice(b"\r\n");
            let mut required = vec![creation];
            for &index in &trace[start + 1..end] {
                let exchange = &state.exchanges[index];
                match exchange.record.command.as_str() {
                    "EXPIRE"
                        if exchange.args.len() == 2
                            && seconds(&exchange.args[1]).map(Duration::from_secs) == Some(ttl) => {
                    }
                    "GET"
                        if exchange.args == [profile.key.clone()]
                            && exchange.response_bytes().ok()? == expected =>
                    {
                        required.push(index)
                    }
                    // Changed values, compound reads and other writes need their own proof.
                    _ => return None,
                }
            }
            required.push(deletion);
            Some(Lifetime {
                epoch,
                creation,
                deletion,
                required,
                ttl,
                established: None,
                closed: None,
                creation_key: None,
                deletion_key: None,
                deletion_event: None,
                failed: false,
                settled: false,
                used_refresh: false,
            })
        })
        .collect()
}

fn seconds(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value)
        .ok()?
        .parse()
        .ok()
        .filter(|&n| n > 0)
}

fn set_ttl(args: &[Vec<u8>]) -> Option<Duration> {
    let value = seconds(&args[3])?;
    if args[2].eq_ignore_ascii_case(b"EX") {
        Some(Duration::from_secs(value))
    } else if args[2].eq_ignore_ascii_case(b"PX") && value % 1000 == 0 {
        Some(Duration::from_millis(value))
    } else {
        None
    }
}

impl Observations {
    pub(super) fn index_closed_expiry(&mut self, owner: usize, profile: &Profile) {
        for (lifetime, proof) in profile.closed_expiry.iter().enumerate() {
            for &index in proof
                .required
                .iter()
                .chain(&profile.epochs[proof.epoch].observations)
            {
                self.expiry_by_exchange
                    .entry(index)
                    .or_default()
                    .push((owner, lifetime));
            }
        }
    }
}

impl RedisReplayState {
    pub(in crate::replay::redis) fn reserve_closed_expiry(
        &mut self,
        index: usize,
        args: &[Vec<u8>],
    ) {
        let Some(entries) = self.observations.expiry_by_exchange.get(&index) else {
            return;
        };
        for &(profile, lifetime) in entries {
            let l = &mut self.observations.profiles[profile].closed_expiry[lifetime];
            if index == l.creation {
                if args.len() != 4 || set_ttl(args) != Some(l.ttl) {
                    l.failed = true;
                    continue;
                }
                l.established = Some(Instant::now());
                l.creation_key = args.first().map(|key| fingerprint(key));
            } else if index == l.deletion {
                if args.len() != 1 {
                    l.failed = true;
                    continue;
                }
                l.deletion_key = args.first().map(|key| fingerprint(key));
            }
        }
    }

    pub(in crate::replay::redis) fn complete_closed_expiry(
        &mut self,
        matched: &MatchedRedisExchange,
    ) {
        let entries = self
            .observations
            .expiry_by_exchange
            .get(&matched.index)
            .cloned()
            .unwrap_or_default();
        for (profile, lifetime) in entries {
            let l = &mut self.observations.profiles[profile].closed_expiry[lifetime];
            if matched.index == l.deletion && l.closed.is_none() {
                l.closed = Some(Instant::now());
                l.deletion_event = matched.report.target_event_index;
            }
            self.settle_closed_expiry(profile, lifetime);
        }
    }

    fn settle_closed_expiry(&mut self, owner: usize, lifetime: usize) {
        let p = &self.observations.profiles[owner];
        let l = &p.closed_expiry[lifetime];
        let Some((start, end)) = l.established.zip(l.closed) else {
            return;
        };
        let Some(elapsed) = end.checked_duration_since(start) else {
            return;
        };
        let same_key = |other: &Profile| {
            other.case == p.case
                && other.target == p.target
                && other.database == p.database
                && other.resp_version == p.resp_version
                && normalize_optional(other.username.as_deref())
                    == normalize_optional(p.username.as_deref())
                && other.key == p.key
        };
        if l.settled
            || l.failed
            || elapsed >= l.ttl
            || l.creation_key.is_none()
            || l.creation_key != l.deletion_key
            || !l
                .required
                .iter()
                .all(|&i| self.exchanges[i].status.is_consumed())
            || self
                .observations
                .profiles
                .iter()
                .any(|other| same_key(other) && other.failed)
            || self
                .observations
                .in_flight
                .values()
                .any(|&i| same_key(&self.observations.profiles[i]))
        {
            return;
        }
        let epoch = &p.epochs[l.epoch];
        if epoch.observations.is_empty() {
            self.observations.profiles[owner].closed_expiry[lifetime].settled = true;
            return;
        }
        // A failed actual refresh must never turn into successful omission coverage.
        if epoch.observations.iter().any(|&i| {
            !matches!(
                self.exchanges[i].status,
                ReplayExchangeStatus::Available | ReplayExchangeStatus::Consumed
            )
        }) {
            return;
        }
        let covered = epoch
            .observations
            .iter()
            .filter(|&&i| !self.exchanges[i].status.is_consumed())
            .count();
        let audit = ObservationAudit {
            rule_id: p.rule.clone(),
            case_id: p.case.clone(),
            kind: Kind::Expiry,
            source_key_fingerprint: fingerprint(&p.key),
            target_key_fingerprint: l.creation_key.clone().unwrap(),
            target_event_index: l.deletion_event,
            source_witness: reference(&self.exchanges[epoch.observations[0]]),
            source_epoch_mutation: Some(reference(&self.exchanges[l.creation])),
            covered_source_observations: covered,
            coverage: Some(Coverage::InitialExpiryUntilDelete {
                source_deletion: reference(&self.exchanges[l.deletion]),
                ttl_seconds: l.ttl.as_secs(),
                target_lifetime_ms: elapsed.as_millis(),
            }),
        };
        for &index in &epoch.observations {
            self.exchanges[index].status = ReplayExchangeStatus::Consumed;
            self.exchanges[index].matched_once = true;
        }
        self.observations.profiles[owner].closed_expiry[lifetime].settled = true;
        if covered > 0 {
            if self.observations.audits.len() < 1000 {
                self.observations.audits.push(audit);
            } else {
                self.observations.omitted += 1;
            }
        }
    }

    pub(in crate::replay::redis) fn fail_closed_expiry(&mut self, index: usize) {
        if let Some(entries) = self.observations.expiry_by_exchange.get(&index) {
            for &(profile, lifetime) in entries {
                self.observations.profiles[profile].closed_expiry[lifetime].failed = true;
            }
        }
    }
}

fn reference(exchange: &ReplayExchange) -> CommandExchangeRefReport {
    CommandExchangeRefReport {
        case_id: exchange.case_id.clone(),
        source: exchange.source,
        connection_id: exchange.record.connection_id,
        sequence: exchange.record.sequence,
        command: exchange.record.command.clone(),
    }
}
