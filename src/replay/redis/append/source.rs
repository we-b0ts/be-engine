//! The planner and runtime share complete Source byte-stream validation.
use super::*;
use crate::replay::policy::native_projection::NativeSourceCase;

pub(in crate::replay) fn validate_source(
    contracts: &crate::replay::policy::request_contract::RequestContracts,
    cases: &[NativeSourceCase<'_>],
) -> Result<BTreeMap<String, usize>> {
    let mut state = super::super::native_source::source_inventory(contracts, cases, |effect| {
        matches!(effect, NativeEffect::RedisAppendStream)
    })?;
    for case in cases {
        state.prepare_append_case(case.id)?;
    }
    let mut counts = BTreeMap::new();
    for profile in state.append_streams.profiles {
        *counts.entry(profile.rule).or_default() += profile.pieces.len();
    }
    Ok(counts)
}
