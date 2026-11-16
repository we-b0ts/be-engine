//! Source proof admits only unchanged absent values and no-op same-key cleanup.
use super::*;
use crate::policy::runtime::native_projection::NativeSourceCase;

pub(super) fn prepare(
    state: &RedisReplayState,
    case: &str,
    rule: &str,
    seed: &ReplayExchange,
) -> Result<Profile> {
    traffic_protocol_redis::storage::prove_read_commutation(
        &state.exchanges,
        &state.connection_scopes,
        case,
        rule,
        seed,
    )
}

pub(crate) fn validate_source(
    contracts: &crate::policy::runtime::request_contract::RequestContracts,
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
