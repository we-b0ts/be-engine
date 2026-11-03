//! Complete Case/key proof. Unknown writers, implicit expiry and TTL reads fail closed.
use super::*;

/// A global declaration does not turn historical, read-only state into an
/// owned lifetime. The ordinary finite exchanges still validate those reads.
pub(super) fn has_owned_set(
    state: &RedisReplayState,
    case: &str,
    seed: &ReplayExchange,
) -> Result<bool> {
    let Some(key) = seed.args.first() else {
        return Ok(false);
    };
    for exchange in &state.exchanges {
        if exchange.source == ReplaySource::Case
            && exchange.case_id.as_deref() == Some(case)
            && exchange.record.database == seed.record.database
            && target_matches(
                &TargetKey {
                    host: seed.record.target_host.clone(),
                    port: seed.record.target_port,
                },
                &exchange.record.target_host,
                exchange.record.target_port,
            )
            && exchange.record.resp_version == seed.record.resp_version
            && normalize_optional(exchange.record.username.as_deref())
                == normalize_optional(seed.record.username.as_deref())
            && exchange.record.outcome == DependencyExchangeOutcome::Response
            && supported_set(exchange, key)
            && exchange.response_bytes()? == b"+OK\r\n"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn supported_set(exchange: &ReplayExchange, key: &[u8]) -> bool {
    exchange.record.command == "SET"
        && matches!(exchange.args.len(), 2 | 4)
        && exchange
            .args
            .first()
            .is_some_and(|selected| selected == key)
}

pub(super) fn prepare(
    state: &RedisReplayState,
    case: &str,
    rule: &str,
    kind: Kind,
    seed: &ReplayExchange,
    transient_nil: bool,
) -> Result<Option<Profile>> {
    let mut profile = Profile {
        case: case.into(),
        rule: rule.into(),
        kind,
        transient_nil,
        target: TargetKey {
            host: seed.record.target_host.clone(),
            port: seed.record.target_port,
        },
        database: seed.record.database,
        username: seed.record.username.clone(),
        resp_version: seed.record.resp_version,
        key: seed
            .args
            .first()
            .context("observation Source key missing")?
            .clone(),
        finite_prefix: vec![],
        initial_accesses: vec![],
        epochs: vec![Epoch {
            mutation: None,
            observations: vec![],
        }],
        valid_for_seconds: None,
        prepared_at: chrono::Utc::now(),
        failed: false,
        closed_expiry: vec![],
    };
    let mut timeline = Vec::new();
    for (index, e) in state.exchanges.iter().enumerate().filter(|(_, e)| {
        e.record.database == profile.database
            && target_matches(&profile.target, &e.record.target_host, e.record.target_port)
    }) {
        if e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case) {
            ensure!(
                !matches!(
                    e.record.command.as_str(),
                    "MULTI" | "EXEC" | "DISCARD" | "WATCH" | "UNWATCH" | "MONITOR"
                ),
                "state observations cannot relax transactional or watched Cases"
            );
        }
        if !super::super::key_access::touches(&e.record.command, &e.args, &profile.key) {
            continue;
        }
        if super::super::case_scope::is_other_ordinary_exchange(case, e) {
            // Another ordinary Case owns its own state, observations and mutations.
            continue;
        }
        ensure!(
            e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case),
            "state observation key overlaps Global or explicitly shared inventory"
        );
        ensure!(
            e.shared_rule_id.is_none()
                && !e.reusable_snapshot
                && !e.record.cache_snapshot_hit
                && e.record.cache_snapshot_rule.is_none()
                && !e.record.session_setup
                && e.record.run_owner_kind().is_none()
                && e.record.outcome == DependencyExchangeOutcome::Response
                && e.record.resp_version == profile.resp_version
                && normalize_optional(e.record.username.as_deref())
                    == normalize_optional(profile.username.as_deref())
                && !state.connection_scopes.is_stateful(e),
            "state observations require ordinary successful Case exchanges with one user/protocol"
        );
        timeline.push((index, e));
    }
    timeline.sort_by_key(|(index, e)| (e.record.started_at(), *index));
    if kind == Kind::StateRead && !has_owned_set(state, case, seed)? {
        return super::state_trace::read_only(profile, &timeline).map(Some);
    }
    if kind == Kind::AbsentRead {
        super::absence::validate_causal_order(&timeline)?;
    } else {
        validate_causal_order(&timeline)?;
    }
    if kind == Kind::AbsentRead {
        super::absence::prepare(&mut profile, &mut timeline)?;
    }
    if matches!(kind, Kind::Read | Kind::StateRead) {
        let mut first_set = None;
        for (position, (_, exchange)) in timeline.iter().enumerate() {
            if supported_set(exchange, &profile.key) && exchange.response_bytes()? == b"+OK\r\n" {
                first_set = Some(position);
                break;
            }
        }
        let first_set =
            first_set.context("read observations have no supported successful Case SET")?;
        let mut unknown_prefix = false;
        for (_, exchange) in &timeline[..first_set] {
            if exchange.record.command == "GET" {
                let response = exchange.response_bytes()?;
                ensure!(
                    response.len() <= crate::value_limits::MAX_VALUE_BYTES,
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
                    .all(|(_, exchange)| exchange.record.command == "GET"),
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
        .and_then(|(_, e)| e.record.earliest_start());
    let last = timeline.last().and_then(|(_, e)| e.record.timestamp);
    for (index, e) in timeline {
        let response = e.response_bytes()?;
        ensure!(
            response.len() <= crate::value_limits::MAX_VALUE_BYTES,
            "state observation response exceeds bounds"
        );
        match e.record.command.as_str() {
            "SET" => {
                ensure!(
                    kind != Kind::AbsentRead,
                    "absent read observations do not permit SET mutations"
                );
                ensure!(
                    e.args.first() == Some(&profile.key)
                        && matches!(e.args.len(), 2 | 4)
                        && response == b"+OK\r\n",
                    "state observation requires a successful unconditional SET"
                );
                ensure!(
                    e.args[1].len() <= crate::value_limits::MAX_VALUE_BYTES,
                    "state observation SET exceeds bounds"
                );
                if e.args.len() == 4 {
                    positive_ttl(&mut profile, &e.args[2], &e.args[3])?;
                }
                value = Some(e.args[1].clone());
                alive = Some(true);
                new_epoch(&mut profile, index)?;
            }
            "DEL" | "UNLINK" => {
                let removed = integer(&response)?;
                let initial_absence = kind == Kind::AbsentRead && profile.epochs.len() == 1;
                ensure!(
                    usize::try_from(removed).is_ok_and(|n| n <= e.args.len())
                        && alive.is_none_or(|alive| {
                            removed >= i64::from(alive)
                                && (initial_absence
                                    || e.args.len() != 1
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
                    e.args == [profile.key.clone()],
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
                    e.args.len() == 2
                        && e.args[0] == profile.key
                        && integer(&response)? == 1
                        && alive != Some(false),
                    "state observation supports only successful positive-TTL refreshes on a proven existing key"
                );
                positive_ttl(
                    &mut profile,
                    if e.record.command == "EXPIRE" {
                        b"EX"
                    } else {
                        b"PX"
                    },
                    &e.args[1],
                )?;
                alive = Some(true);
                if kind == Kind::Expiry {
                    ensure!(
                        e.record.command == "EXPIRE",
                        "expiry refresh cannot mix EXPIRE and PEXPIRE"
                    );
                    if let Some(expected) = &refresh {
                        ensure!(
                            expected == &e.args,
                            "expiry refresh changes the TTL within one key"
                        );
                    } else {
                        refresh = Some(e.args.clone());
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
                    e.args.len() == 2 && e.args[0] == profile.key && integer(&response)? >= 0,
                    "expiry refresh needs a successful Case APPEND"
                );
                if alive != Some(true) {
                    new_epoch(&mut profile, index)?;
                }
                alive = Some(true);
            }
            "RPUSH" | "LPUSH" if kind == Kind::Expiry => {
                ensure!(
                    e.args.len() >= 2 && e.args[0] == profile.key && integer(&response)? > 0,
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
            let command = state.exchanges[index].record.command.as_str();
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
        profile.closed_expiry = closed_expiry::prove(state, &profile, &key_trace);
        if !observed {
            // A Source SET/GET/DEL proof may support Target refreshes even when
            // Source buffering required none. No incomplete proof installs a profile.
            return Ok((!profile.closed_expiry.is_empty()).then_some(profile));
        }
    }
    ensure!(observed, "state observations lack Source witnesses");
    Ok(Some(profile))
}

fn observes_absence(exchange: &ReplayExchange, key: &[u8], response: &[u8]) -> bool {
    let single_key = exchange.args.len() == 1 && exchange.args[0] == key;
    match exchange.record.command.as_str() {
        "GET" => single_key && (response == b"$-1\r\n" || response == b"_\r\n"),
        "EXISTS" | "LLEN" => single_key && response == b":0\r\n",
        "TYPE" => single_key && (response == b"+none\r\n" || response == b"$4\r\nnone\r\n"),
        "LRANGE" => {
            exchange.args.len() == 3
                && exchange.args[0] == key
                && exchange.args.get(1).is_some_and(|arg| arg == b"0")
                && exchange.args.get(2).is_some_and(|arg| arg == b"-1")
                && response == b"*0\r\n"
        }
        // Empty strings/ranges and a nil MGET member do not prove absence:
        // MGET also returns nil for an existing key of a non-string type.
        _ => false,
    }
}

pub(in crate::replay::redis) fn validate_causal_order(
    timeline: &[(usize, &ReplayExchange)],
) -> Result<()> {
    let mut lanes = BTreeMap::new();
    let mut previous: Option<&ReplayExchange> = None;
    for (_, exchange) in timeline {
        if let Some(sequence) =
            lanes.insert(exchange.record.connection_id, exchange.record.sequence)
        {
            ensure!(
                sequence < exchange.record.sequence,
                "state observation Source clocks reverse a lane"
            );
        }
        if let Some(before) = previous {
            require_causal_order(before, exchange)?;
        }
        previous = Some(exchange);
    }
    Ok(())
}

pub(super) fn require_causal_order(before: &ReplayExchange, after: &ReplayExchange) -> Result<()> {
    ensure!(
        before.record.connection_id == after.record.connection_id
            || before
                .record
                .timestamp
                .zip(after.record.earliest_start())
                .is_some_and(|(end, start)| end <= start),
        "state observation Source accesses overlap or lack causal clocks: \
         before connection={} sequence={} start={:?} end={:?}; \
         after connection={} sequence={} start={:?} end={:?}",
        before.record.connection_id,
        before.record.sequence,
        before.record.earliest_start(),
        before.record.timestamp,
        after.record.connection_id,
        after.record.sequence,
        after.record.earliest_start(),
        after.record.timestamp,
    );
    Ok(())
}

pub(super) fn new_epoch(profile: &mut Profile, mutation: usize) -> Result<()> {
    ensure!(
        profile.epochs.len() < 1024,
        "state observations exceed Source lifetime limit"
    );
    profile.epochs.push(Epoch {
        mutation: Some(mutation),
        observations: vec![],
    });
    Ok(())
}

fn positive_ttl(profile: &mut Profile, unit: &[u8], value: &[u8]) -> Result<()> {
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
