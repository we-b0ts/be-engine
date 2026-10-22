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
    for (index, exchange) in state.exchanges.iter().enumerate().filter(|(_, e)| {
        e.record.database == profile.database
            && target_matches(&profile.target, &e.record.target_host, e.record.target_port)
            && super::super::key_access::touches(&e.record.command, &e.args, &profile.key)
    }) {
        ensure!(
            exchange.source == ReplaySource::Case && exchange.case_id.as_deref() == Some(case),
            "read commutation key overlaps another Case or Global inventory"
        );
        ensure!(
            exchange.shared_rule_id.is_none()
                && !exchange.reusable_snapshot
                && exchange.record.cache_snapshot_rule.is_none()
                && !exchange.record.cache_snapshot_hit
                && !exchange.record.session_setup
                && exchange.record.global_dependency_reason.is_none()
                && exchange.record.outcome == DependencyExchangeOutcome::Response
                && exchange.record.resp_version == seed.record.resp_version
                && normalize_optional(exchange.record.username.as_deref())
                    == normalize_optional(seed.record.username.as_deref()),
            "read commutation requires ordinary successful Case exchanges with one protocol/user"
        );
        let response = exchange.response_bytes()?;
        ensure!(
            exchange.args.len() == 1 && exchange.args[0] == profile.key,
            "read commutation requires single-key observations or cleanup"
        );
        match exchange.record.command.as_str() {
            "GET" => {
                ensure!(
                    !state
                        .connection_scopes
                        .is_stateful(exchange.record.connection_id),
                    "read commutation cannot relax stateful or transactional Source lanes"
                );
                ensure!(
                    response == b"$-1\r\n",
                    "read commutation requires unchanged nil GET responses"
                );
                profile.reads.push(index);
            }
            // DEL 0 cannot change the observed absent value. It remains finite
            // and ordered against every other ordinary dependency.
            "DEL" => ensure!(
                response == b":0\r\n",
                "read commutation cleanup changed the key"
            ),
            _ => anyhow::bail!("read commutation key has a mutation or unsupported observation"),
        }
    }
    ensure!(
        !profile.reads.is_empty(),
        "read commutation lacks a Source observation"
    );
    Ok(profile)
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
