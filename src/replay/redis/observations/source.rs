//! Complete Case/key proof. Unknown writers, implicit expiry and TTL reads fail closed.
use super::*;

pub(super) fn prepare(
    state: &RedisReplayState,
    case: &str,
    rule: &str,
    kind: Kind,
    seed: &ReplayExchange,
) -> Result<Profile> {
    let mut profile = Profile {
        case: case.into(),
        rule: rule.into(),
        kind,
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
        epochs: vec![Epoch {
            mutation: None,
            observations: vec![],
        }],
        valid_for_seconds: None,
        prepared_at: chrono::Utc::now(),
        failed: false,
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
        ensure!(
            e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case),
            "state observation key overlaps another Case or Global inventory"
        );
        ensure!(
            e.shared_rule_id.is_none()
                && !e.reusable_snapshot
                && !e.record.cache_snapshot_hit
                && e.record.cache_snapshot_rule.is_none()
                && !e.record.session_setup
                && e.record.global_dependency_reason.is_none()
                && e.record.outcome == DependencyExchangeOutcome::Response
                && e.record.resp_version == profile.resp_version
                && normalize_optional(e.record.username.as_deref())
                    == normalize_optional(profile.username.as_deref())
                && !state.connection_scopes.is_stateful(e.record.connection_id),
            "state observations require ordinary successful Case exchanges with one user/protocol"
        );
        timeline.push((index, e));
    }
    timeline.sort_by_key(|(index, e)| (e.record.started_at(), *index));
    let mut lanes = BTreeMap::new();
    let mut previous: Option<&ReplayExchange> = None;
    let mut value: Option<Vec<u8>> = None;
    let mut alive = false;
    let mut refresh: Option<Vec<Vec<u8>>> = None;
    let first = timeline
        .first()
        .and_then(|(_, e)| e.record.earliest_start());
    let last = timeline.last().and_then(|(_, e)| e.record.timestamp);
    for (index, e) in timeline {
        if let Some(sequence) = lanes.insert(e.record.connection_id, e.record.sequence) {
            ensure!(
                sequence < e.record.sequence,
                "state observation Source clocks reverse a lane"
            );
        }
        if let Some(p) = previous {
            ensure!(
                p.record.connection_id == e.record.connection_id
                    || p.record
                        .timestamp
                        .zip(e.record.earliest_start())
                        .is_some_and(|(end, start)| end <= start),
                "state observation Source accesses overlap or lack causal clocks"
            );
        }
        previous = Some(e);
        let response = e.response_bytes()?;
        ensure!(
            response.len() <= 1024 * 1024,
            "state observation response exceeds bounds"
        );
        match e.record.command.as_str() {
            "SET" => {
                ensure!(
                    e.args.first() == Some(&profile.key)
                        && matches!(e.args.len(), 2 | 4)
                        && response == b"+OK\r\n",
                    "state observation requires a successful unconditional SET"
                );
                ensure!(
                    e.args[1].len() <= 1024 * 1024,
                    "state observation SET exceeds bounds"
                );
                if e.args.len() == 4 {
                    positive_ttl(&mut profile, &e.args[2], &e.args[3])?;
                }
                value = Some(e.args[1].clone());
                alive = true;
                new_epoch(&mut profile, index)?;
            }
            "DEL" | "UNLINK" => {
                let removed = integer(&response)?;
                ensure!(
                    removed >= i64::from(alive)
                        && usize::try_from(removed).is_ok_and(|n| n <= e.args.len())
                        && (e.args.len() != 1 || removed == i64::from(alive)),
                    "state observation deletion has an invalid response"
                );
                value = None;
                alive = false;
                new_epoch(&mut profile, index)?;
            }
            "GET" if kind == Kind::Read => {
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
                        && alive,
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
                    profile.epochs.last_mut().unwrap().observations.push(index);
                }
            }
            "APPEND" if kind == Kind::Expiry => {
                ensure!(
                    e.args.len() == 2 && e.args[0] == profile.key && integer(&response)? >= 0,
                    "expiry refresh needs a successful Case APPEND"
                );
                if !alive {
                    new_epoch(&mut profile, index)?;
                }
                alive = true;
            }
            "RPUSH" | "LPUSH" if kind == Kind::Expiry => {
                ensure!(
                    e.args.len() >= 2 && e.args[0] == profile.key && integer(&response)? > 0,
                    "expiry refresh needs a successful Case list creation"
                );
                if !alive {
                    new_epoch(&mut profile, index)?;
                }
                alive = true;
            }
            "LSET" if kind == Kind::Expiry => ensure!(
                alive && response == b"+OK\r\n",
                "expiry refresh LSET lacks a known list"
            ),
            "GET" | "MGET" | "GETRANGE" | "STRLEN" | "LRANGE" | "LLEN" | "EXISTS" | "TYPE"
                if kind == Kind::Expiry => {}
            _ => anyhow::bail!(
                "state observation key has an unsupported mutation, script or expiry observation"
            ),
        }
    }
    ensure!(
        profile.epochs.iter().any(|e| !e.observations.is_empty()),
        "state observations lack Source witnesses"
    );
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
    Ok(profile)
}

fn new_epoch(profile: &mut Profile, mutation: usize) -> Result<()> {
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

fn integer(bytes: &[u8]) -> Result<i64> {
    let value = bytes
        .strip_prefix(b":")
        .and_then(|v| v.strip_suffix(b"\r\n"))
        .context("expected a successful RESP integer")?;
    Ok(std::str::from_utf8(value)?.parse()?)
}
