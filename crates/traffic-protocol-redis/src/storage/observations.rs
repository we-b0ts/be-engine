//! Source-proven Redis key observations, independent of execution and publication.
use super::{
    StorageExchange, is_other_ordinary_exchange, normalized_username as normalize_optional,
    target_matches,
};
use crate::{RedisFrameKind, frame_kind as redis_frame_kind, session_binding::ConnectionScopes};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use traffic_model::{DependencyExchangeOutcome, attribution::DependencyScope};
use traffic_protocol::connection::Endpoint;
mod absence;
mod expiry;
mod state_trace;
pub use expiry::{ExpiryProof, set_ttl};
pub const MAX_OBSERVATIONS: usize = 4096;

pub struct Configuration<'a> {
    pub case: &'a str,
    pub rule: &'a str,
    pub kind: Kind,
    pub transient_nil: bool,
    pub prepared_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Read,
    StateRead,
    AbsentRead,
    Expiry,
}

impl Kind {
    pub fn is_read(self) -> bool {
        matches!(self, Self::Read | Self::StateRead | Self::AbsentRead)
    }
}

#[derive(Debug)]
pub struct Epoch {
    pub mutation: Option<usize>,
    pub observations: Vec<usize>,
    pub predecessors: Vec<usize>,
}

#[derive(Debug)]
pub struct Profile<L> {
    pub case: String,
    pub rule: String,
    pub kind: Kind,
    pub transient_nil: bool,
    pub target: Endpoint,
    pub database: i64,
    pub username: Option<String>,
    pub resp_version: u8,
    pub key: Vec<u8>,
    pub finite_prefix: Vec<usize>,
    pub initial_accesses: Vec<usize>,
    pub epochs: Vec<Epoch>,
    pub valid_for_seconds: Option<u64>,
    pub prepared_at: chrono::DateTime<chrono::Utc>,
    pub failed: bool,
    pub closed_expiry: Vec<L>,
}

/// A global declaration does not turn historical, read-only state into an
/// owned lifetime. The ordinary finite exchanges still validate those reads.
pub fn has_owned_set<E: StorageExchange>(exchanges: &[E], case: &str, seed: &E) -> Result<bool> {
    let Some(key) = seed.arguments().first() else {
        return Ok(false);
    };
    for exchange in exchanges {
        if exchange.source() == DependencyScope::Case
            && exchange.case_id() == Some(case)
            && exchange.native_record().database == seed.native_record().database
            && target_matches(
                &Endpoint {
                    host: seed.native_record().target_host.clone(),
                    port: seed.native_record().target_port,
                },
                &exchange.native_record().target_host,
                exchange.native_record().target_port,
            )
            && exchange.native_record().resp_version == seed.native_record().resp_version
            && normalize_optional(exchange.native_record().username.as_deref())
                == normalize_optional(seed.native_record().username.as_deref())
            && exchange.native_record().outcome == DependencyExchangeOutcome::Response
            && supported_set(exchange, key)
            && exchange.response_bytes()? == b"+OK\r\n"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn supported_set<E: StorageExchange>(exchange: &E, key: &[u8]) -> bool {
    exchange.native_record().command == "SET"
        && matches!(exchange.arguments().len(), 2 | 4)
        && exchange
            .arguments()
            .first()
            .is_some_and(|selected| selected == key)
}

pub fn prepare<E: StorageExchange, L: From<ExpiryProof>>(
    exchanges: &[E],
    scopes: &ConnectionScopes,
    configuration: Configuration<'_>,
    seed: &E,
) -> Result<Option<Profile<L>>> {
    let Configuration {
        case,
        rule,
        kind,
        transient_nil,
        prepared_at,
    } = configuration;
    let mut profile = Profile {
        case: case.into(),
        rule: rule.into(),
        kind,
        transient_nil,
        target: Endpoint {
            host: seed.native_record().target_host.clone(),
            port: seed.native_record().target_port,
        },
        database: seed.native_record().database,
        username: seed.native_record().username.clone(),
        resp_version: seed.native_record().resp_version,
        key: seed
            .arguments()
            .first()
            .context("observation Source key missing")?
            .clone(),
        finite_prefix: vec![],
        initial_accesses: vec![],
        epochs: vec![Epoch {
            mutation: None,
            observations: vec![],
            predecessors: vec![],
        }],
        valid_for_seconds: None,
        prepared_at,
        failed: false,
        closed_expiry: vec![],
    };
    let mut timeline = Vec::new();
    for (index, e) in exchanges.iter().enumerate().filter(|(_, e)| {
        e.native_record().database == profile.database
            && target_matches(
                &profile.target,
                &e.native_record().target_host,
                e.native_record().target_port,
            )
    }) {
        if e.source() == DependencyScope::Case && e.case_id() == Some(case) {
            ensure!(
                !matches!(
                    e.native_record().command.as_str(),
                    "MULTI" | "EXEC" | "DISCARD" | "WATCH" | "UNWATCH" | "MONITOR"
                ),
                "state observations cannot relax transactional or watched Cases"
            );
        }
        if !crate::key_access::touches(&e.native_record().command, e.arguments(), &profile.key) {
            continue;
        }
        if is_other_ordinary_exchange(case, e) {
            // Another ordinary Case owns its own state, observations and mutations.
            continue;
        }
        ensure!(
            e.source() == DependencyScope::Case && e.case_id() == Some(case),
            "state observation key overlaps Global or explicitly shared inventory"
        );
        ensure!(
            !e.explicitly_shared()
                && !e.native_record().cache_snapshot_hit
                && e.native_record().cache_snapshot_rule.is_none()
                && !e.native_record().session_setup
                && e.native_record().run_owner_kind().is_none()
                && e.native_record().outcome == DependencyExchangeOutcome::Response
                && e.native_record().resp_version == profile.resp_version
                && normalize_optional(e.native_record().username.as_deref())
                    == normalize_optional(profile.username.as_deref())
                && !scopes.is_stateful(e),
            "state observations require ordinary successful Case exchanges with one user/protocol"
        );
        timeline.push((index, e));
    }
    timeline.sort_by_key(|(index, e)| (e.native_record().source_started_at(), *index));
    if kind == Kind::StateRead && !has_owned_set(exchanges, case, seed)? {
        return state_trace::read_only(exchanges, profile, &timeline).map(Some);
    }
    if kind == Kind::AbsentRead {
        absence::validate_causal_order(&timeline)?;
    } else if kind != Kind::StateRead {
        validate_causal_order(&timeline)?;
    }
    if kind == Kind::AbsentRead {
        absence::prepare(&mut profile, &mut timeline)?;
    }
    if matches!(kind, Kind::Read | Kind::StateRead) {
        let mut first_set = None;
        for (position, &(_, exchange)) in timeline.iter().enumerate() {
            if supported_set(exchange, &profile.key) && exchange.response_bytes()? == b"+OK\r\n" {
                first_set = Some(position);
                break;
            }
        }
        let first_set =
            first_set.context("read observations have no supported successful Case SET")?;
        if kind == Kind::StateRead {
            validate_causal_epochs(&timeline, Some(first_set))?;
        }
        let mut unknown_prefix = false;
        for (_, exchange) in &timeline[..first_set] {
            if exchange.native_record().command == "GET" {
                let response = exchange.response_bytes()?;
                ensure!(
                    response.len() <= traffic_value::MAX_VALUE_BYTES,
                    "state observation response exceeds bounds"
                );
                ensure!(
                    matches!(
                        redis_frame_kind(&bytes::Bytes::copy_from_slice(&response))?,
                        RedisFrameKind::BulkString | RedisFrameKind::Null | RedisFrameKind::Error
                    ),
                    "historical Source GET has an invalid response type"
                );
                unknown_prefix |= response != b"$-1\r\n";
            }
        }
        if unknown_prefix {
            ensure!(
                timeline[..first_set]
                    .iter()
                    .all(|(_, exchange)| exchange.native_record().command == "GET"),
                "unknown initial state prefix cannot hide unsupported writers or expiry observations"
            );
            profile.finite_prefix = timeline
                .drain(..first_set)
                .map(|(index, _)| index)
                .collect();
        }
    }
    let mut value: Option<Vec<u8>> = None;
    // A successful expiry can observe a key that predates this Case. Read-back
    // and absent-read permissions still need their own explicit state proof.
    let mut alive = (kind != Kind::Expiry).then_some(false);
    let mut refresh: Option<Vec<Vec<u8>>> = None;
    let key_trace = timeline.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let first = timeline
        .first()
        .and_then(|(_, e)| e.native_record().earliest_start());
    let last = timeline.last().and_then(|(_, e)| {
        let last = e.native_record().timestamp?;
        Some(if kind == Kind::StateRead {
            timeline
                .iter()
                .filter_map(|(_, e)| e.native_record().timestamp)
                .max()
                .unwrap_or(last)
        } else {
            last
        })
    });
    for (index, e) in timeline {
        let response = e.response_bytes()?;
        ensure!(
            response.len() <= traffic_value::MAX_VALUE_BYTES,
            "state observation response exceeds bounds"
        );
        match e.native_record().command.as_str() {
            "SET" => {
                ensure!(
                    kind != Kind::AbsentRead,
                    "absent read observations do not permit SET mutations"
                );
                ensure!(
                    e.arguments().first() == Some(&profile.key)
                        && matches!(e.arguments().len(), 2 | 4)
                        && response == b"+OK\r\n",
                    "state observation requires a successful unconditional SET"
                );
                ensure!(
                    e.arguments()[1].len() <= traffic_value::MAX_VALUE_BYTES,
                    "state observation SET exceeds bounds"
                );
                if e.arguments().len() == 4 {
                    positive_ttl(&mut profile, &e.arguments()[2], &e.arguments()[3])?;
                }
                value = Some(e.arguments()[1].clone());
                alive = Some(true);
                new_epoch(&mut profile, index)?;
            }
            "DEL" | "UNLINK" => {
                let removed = integer(&response)?;
                let initial_absence = kind == Kind::AbsentRead && profile.epochs.len() == 1;
                ensure!(
                    usize::try_from(removed).is_ok_and(|n| n <= e.arguments().len())
                        && alive.is_none_or(|alive| {
                            removed >= i64::from(alive)
                                && (initial_absence
                                    || e.arguments().len() != 1
                                    || removed == i64::from(alive))
                        }),
                    "state observation deletion has an invalid response"
                );
                value = None;
                alive = Some(false);
                new_epoch(&mut profile, index)?;
            }
            "GET" if kind.is_read() => {
                ensure!(
                    e.arguments() == [profile.key.clone()],
                    "state observations require a single-key GET"
                );
                let expected = match &value {
                    None => b"$-1\r\n".to_vec(),
                    Some(value) => {
                        let mut r = format!("${}\r\n", value.len()).into_bytes();
                        r.extend(value);
                        r.extend(b"\r\n");
                        r
                    }
                };
                ensure!(
                    response == expected,
                    "Source GET does not preserve its known SET/DEL state (unknown initial value or expiry)"
                );
                profile.epochs.last_mut().unwrap().observations.push(index);
            }
            "EXPIRE" | "PEXPIRE" => {
                ensure!(
                    e.arguments().len() == 2
                        && e.arguments()[0] == profile.key
                        && integer(&response)? == 1
                        && alive != Some(false),
                    "state observation supports only successful positive-TTL refreshes on a proven existing key"
                );
                positive_ttl(
                    &mut profile,
                    if e.native_record().command == "EXPIRE" {
                        b"EX"
                    } else {
                        b"PX"
                    },
                    &e.arguments()[1],
                )?;
                alive = Some(true);
                if kind == Kind::Expiry {
                    ensure!(
                        e.native_record().command == "EXPIRE",
                        "expiry refresh cannot mix EXPIRE and PEXPIRE"
                    );
                    if let Some(expected) = &refresh {
                        ensure!(
                            expected.as_slice() == e.arguments(),
                            "expiry refresh changes the TTL within one key"
                        );
                    } else {
                        refresh = Some(e.arguments().to_vec());
                    }
                    if profile.epochs.len() == 1
                        && profile.epochs[0].mutation.is_none()
                        && profile.epochs[0].observations.is_empty()
                    {
                        profile.finite_prefix = key_trace
                            .iter()
                            .take_while(|&&candidate| candidate != index)
                            .copied()
                            .collect();
                    }
                    profile.epochs.last_mut().unwrap().observations.push(index);
                }
            }
            "APPEND" if kind == Kind::Expiry => {
                ensure!(
                    e.arguments().len() == 2
                        && e.arguments()[0] == profile.key
                        && integer(&response)? >= 0,
                    "expiry refresh needs a successful Case APPEND"
                );
                if alive != Some(true) {
                    new_epoch(&mut profile, index)?;
                }
                alive = Some(true);
            }
            "RPUSH" | "LPUSH" if kind == Kind::Expiry => {
                ensure!(
                    e.arguments().len() >= 2
                        && e.arguments()[0] == profile.key
                        && integer(&response)? > 0,
                    "expiry refresh needs a successful Case list creation"
                );
                if alive != Some(true) {
                    new_epoch(&mut profile, index)?;
                }
                alive = Some(true);
            }
            "LSET" if kind == Kind::Expiry => {
                ensure!(
                    alive != Some(false) && response == b"+OK\r\n",
                    "expiry refresh LSET lacks an existing list"
                );
                alive = Some(true);
            }
            "GET" | "MGET" | "GETRANGE" | "STRLEN" | "LRANGE" | "LLEN" | "EXISTS" | "TYPE"
                if kind == Kind::Expiry =>
            {
                ensure!(
                    profile.epochs.len() != 1
                        || profile.epochs[0].observations.is_empty()
                        || !observes_absence(e, &profile.key, &response),
                    "initial existing-key expiry interval contains an absent-key observation"
                );
            }
            _ => anyhow::bail!(
                "state observation key has an unsupported mutation, script or expiry observation"
            ),
        }
    }
    if let Some(ttl) = profile.valid_for_seconds {
        let (first, last) = first
            .zip(last)
            .context("state observations with TTL require complete Source clocks")?;
        ensure!(
            last >= first
                && last.signed_duration_since(first).num_milliseconds()
                    < i64::try_from(ttl.checked_mul(1000).context("TTL overflow")?)?,
            "Source key lifetime reaches or exceeds its TTL; refresh equivalence is not proven"
        );
    }
    let observed = profile
        .epochs
        .iter()
        .any(|epoch| !epoch.observations.is_empty());
    if !observed && kind == Kind::Read && !profile.finite_prefix.is_empty() {
        // Source validation still covers every write and expiry constraint,
        // but historical reads cannot supply a write-to-read witness.
        return Ok(None);
    }
    if kind == Kind::Expiry {
        let first_mutation = profile.epochs.iter().find_map(|epoch| epoch.mutation);
        for &index in &key_trace {
            if Some(index) == first_mutation && profile.initial_accesses.is_empty() {
                break;
            }
            let command = exchanges[index].native_record().command.as_str();
            if !matches!(command, "EXPIRE" | "PEXPIRE") {
                ensure!(
                    profile.initial_accesses.len() < MAX_OBSERVATIONS,
                    "initial existing-key accesses exceed the Source observation limit"
                );
                profile.initial_accesses.push(index);
            }
            if Some(index) == first_mutation {
                break;
            }
        }
        profile.closed_expiry = expiry::prove(exchanges, &profile, &key_trace)
            .into_iter()
            .map(L::from)
            .collect();
        if !observed {
            // A Source SET/GET/DEL proof may support Target refreshes even when
            // Source buffering required none. No incomplete proof installs a profile.
            return Ok((!profile.closed_expiry.is_empty()).then_some(profile));
        }
    }
    ensure!(observed, "state observations lack Source witnesses");
    Ok(Some(profile))
}

fn observes_absence<E: StorageExchange>(exchange: &E, key: &[u8], response: &[u8]) -> bool {
    let single_key = exchange.arguments().len() == 1 && exchange.arguments()[0] == key;
    match exchange.native_record().command.as_str() {
        "GET" => single_key && (response == b"$-1\r\n" || response == b"_\r\n"),
        "EXISTS" | "LLEN" => single_key && response == b":0\r\n",
        "TYPE" => single_key && (response == b"+none\r\n" || response == b"$4\r\nnone\r\n"),
        "LRANGE" => {
            exchange.arguments().len() == 3
                && exchange.arguments()[0] == key
                && exchange.arguments().get(1).is_some_and(|arg| arg == b"0")
                && exchange.arguments().get(2).is_some_and(|arg| arg == b"-1")
                && response == b"*0\r\n"
        }
        // Empty strings/ranges and a nil MGET member do not prove absence:
        // MGET also returns nil for an existing key of a non-string type.
        _ => false,
    }
}

pub fn validate_causal_order<E: StorageExchange>(timeline: &[(usize, &E)]) -> Result<()> {
    validate_causal_epochs(timeline, None)
}

fn validate_causal_epochs<E: StorageExchange>(
    timeline: &[(usize, &E)],
    owned_from: Option<usize>,
) -> Result<()> {
    let mut lanes = BTreeMap::new();
    let mut boundary = None;
    // Keep the latest completing read on every lane. A short overlapping
    // GET cannot hide a longer read from the next mutation's barrier.
    let mut reads = BTreeMap::<_, &E>::new();
    let multiple_lanes = owned_from.is_some()
        && timeline.first().is_some_and(|(_, first)| {
            timeline.iter().any(|(_, exchange)| {
                exchange.native_record().connection_id != first.native_record().connection_id
            })
        });
    for (position, &(_, exchange)) in timeline.iter().enumerate() {
        if let Some(sequence) = lanes.insert(
            exchange.native_record().connection_id,
            exchange.native_record().sequence,
        ) {
            ensure!(
                sequence < exchange.native_record().sequence,
                "state observation Source clocks reverse a lane"
            );
        }
        if multiple_lanes {
            ensure!(
                exchange
                    .native_record()
                    .earliest_start()
                    .zip(exchange.native_record().timestamp)
                    .is_some_and(|(start, end)| start <= end),
                "concurrent owned state observations require complete Source clocks"
            );
        }
        if let Some(before) = boundary {
            require_causal_order(before, exchange)?;
        }
        if owned_from.is_some_and(|first_set| position > first_set)
            && exchange.native_record().command == "GET"
        {
            let read = reads
                .entry(exchange.native_record().connection_id)
                .or_insert(exchange);
            if read.native_record().timestamp < exchange.native_record().timestamp {
                *read = exchange;
            }
        } else {
            for read in std::mem::take(&mut reads).into_values() {
                require_causal_order(read, exchange)?;
            }
            boundary = Some(exchange);
        }
    }
    Ok(())
}

pub(super) fn require_causal_order<E: StorageExchange>(before: &E, after: &E) -> Result<()> {
    ensure!(
        before.native_record().connection_id == after.native_record().connection_id
            || before
                .native_record()
                .timestamp
                .zip(after.native_record().earliest_start())
                .is_some_and(|(end, start)| end <= start),
        "state observation Source accesses overlap or lack causal clocks: \
         before connection={} sequence={} start={:?} end={:?}; \
         after connection={} sequence={} start={:?} end={:?}",
        before.native_record().connection_id,
        before.native_record().sequence,
        before.native_record().earliest_start(),
        before.native_record().timestamp,
        after.native_record().connection_id,
        after.native_record().sequence,
        after.native_record().earliest_start(),
        after.native_record().timestamp,
    );
    Ok(())
}

pub(super) fn new_epoch<L>(profile: &mut Profile<L>, mutation: usize) -> Result<()> {
    ensure!(
        profile.epochs.len() < 1024,
        "state observations exceed Source lifetime limit"
    );
    profile.epochs.push(Epoch {
        mutation: Some(mutation),
        observations: vec![],
        predecessors: vec![],
    });
    Ok(())
}

fn positive_ttl<L>(profile: &mut Profile<L>, unit: &[u8], value: &[u8]) -> Result<()> {
    ensure!(
        value.iter().all(u8::is_ascii_digit) && !value.is_empty(),
        "state observations require a literal positive TTL"
    );
    let mut seconds = std::str::from_utf8(value)?.parse::<u64>()?;
    if unit.eq_ignore_ascii_case(b"PX") {
        ensure!(
            seconds % 1000 == 0,
            "state observation TTL requires whole seconds"
        );
        seconds /= 1000;
    } else {
        ensure!(
            unit.eq_ignore_ascii_case(b"EX"),
            "state observations do not authorize SET expiry options"
        );
    }
    ensure!(
        seconds > 0 && seconds <= i64::MAX as u64 / 1000,
        "state observation TTL exceeds bounds"
    );
    profile.valid_for_seconds = Some(
        profile
            .valid_for_seconds
            .map_or(seconds, |old| old.min(seconds)),
    );
    Ok(())
}

pub(super) fn integer(bytes: &[u8]) -> Result<i64> {
    let value = bytes
        .strip_prefix(b":")
        .and_then(|v| v.strip_suffix(b"\r\n"))
        .context("expected a successful RESP integer")?;
    Ok(std::str::from_utf8(value)?.parse()?)
}
