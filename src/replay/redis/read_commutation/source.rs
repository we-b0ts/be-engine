//! Source proof admits only unchanged absent values and no-op same-key cleanup.
use super::*;
use crate::replay::policy::native_projection::NativeSourceCase;

pub(super) fn prepare(
    state: &RedisReplayState,
    case: &str,
    rule: &str,
    seed: &ReplayExchange,
) -> Result<Profile> {
    let mut profile = Profile {
        case: case.into(),
        target: TargetKey {
            host: seed.record.target_host.clone(),
            port: seed.record.target_port,
        },
        database: seed.record.database,
        key: seed
            .args
            .first()
            .context("read commutation Source key missing")?
            .clone(),
        rule: rule.into(),
        reads: Vec::new(),
    };
    let mut cleanups = Vec::new();
    for (index, exchange) in state.exchanges.iter().enumerate().filter(|(_, e)| {
        e.record.database == profile.database
            && target_matches(&profile.target, &e.record.target_host, e.record.target_port)
            && super::super::key_access::touches(&e.record.command, &e.args, &profile.key)
    }) {
        if super::super::case_scope::is_other_ordinary_exchange(case, exchange) {
            continue;
        }
        ensure!(
            exchange.source == ReplaySource::Case && exchange.case_id.as_deref() == Some(case),
            "read commutation key overlaps Global or shared inventory"
        );
        ensure!(
            exchange.shared_rule_id.is_none()
                && !exchange.reusable_snapshot
                && exchange.record.cache_snapshot_rule.is_none()
                && !exchange.record.cache_snapshot_hit
                && !exchange.record.session_setup
                && exchange.record.run_owner_kind().is_none()
                && exchange.record.outcome == DependencyExchangeOutcome::Response
                && exchange.record.resp_version == seed.record.resp_version
                && normalize_optional(exchange.record.username.as_deref())
                    == normalize_optional(seed.record.username.as_deref()),
            "read commutation requires ordinary successful Case exchanges with one protocol/user"
        );
        let response = exchange.response_bytes()?;
        match exchange.record.command.as_str() {
            "GET" => {
                ensure!(
                    exchange.args == [profile.key.clone()],
                    "read commutation requires single-key observations"
                );
                ensure!(
                    !state.connection_scopes.is_stateful(exchange),
                    "read commutation cannot relax stateful or transactional Source lanes"
                );
                ensure!(
                    response == b"$-1\r\n",
                    "read commutation requires unchanged nil GET responses"
                );
                profile.reads.push(index);
            }
            "DEL" => cleanups.push((exchange, response)),
            _ => anyhow::bail!("read commutation key has a mutation or unsupported observation"),
        }
    }
    ensure!(
        !profile.reads.is_empty(),
        "read commutation lacks a Source observation"
    );
    for (cleanup, response) in cleanups {
        validate_cleanup(state, &profile, cleanup, &response)?;
    }
    Ok(profile)
}

fn validate_cleanup(
    state: &RedisReplayState,
    profile: &Profile,
    cleanup: &ReplayExchange,
    response: &[u8],
) -> Result<()> {
    if cleanup.args == [profile.key.clone()] {
        ensure!(
            response == b":0\r\n",
            "read commutation cleanup changed the key"
        );
        return Ok(());
    }
    // A final multi-key DEL may remove other keys. The selected key must
    // already have been observed absent before cleanup, with no writer in the
    // complete scoped inventory. Keep the DEL itself finite and lane-ordered.
    ensure!(
        profile.reads.iter().all(|&index| {
            let read = &state.exchanges[index];
            if read.record.connection_id == cleanup.record.connection_id {
                read.record.sequence < cleanup.record.sequence
            } else {
                read.record
                    .timestamp
                    .zip(cleanup.record.earliest_start())
                    .is_some_and(|(end, start)| end <= start)
            }
        }),
        "read commutation multi-key cleanup must follow every nil observation"
    );
    let other_keys = cleanup
        .args
        .iter()
        .filter(|key| **key != profile.key)
        .collect::<BTreeSet<_>>()
        .len();
    let removed = response
        .strip_prefix(b":")
        .and_then(|value| value.strip_suffix(b"\r\n"))
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<usize>().ok());
    ensure!(
        other_keys > 0 && removed.is_some_and(|removed| removed <= other_keys),
        "read commutation multi-key cleanup count cannot include the absent key"
    );
    Ok(())
}

pub(in crate::replay) fn validate_source(
    contracts: &crate::replay::policy::request_contract::RequestContracts,
    cases: &[NativeSourceCase<'_>],
) -> Result<BTreeMap<String, usize>> {
    let mut state = super::super::native_source::source_inventory(contracts, cases, |effect| {
        matches!(effect, NativeEffect::RedisReadCommutation(_))
    })?;
    for case in cases {
        state.prepare_read_commutation(case.id)?;
    }
    let mut counts = BTreeMap::new();
    for profile in state.read_commutation.profiles {
        *counts.entry(profile.rule).or_default() += profile.reads.len();
    }
    Ok(counts)
}
