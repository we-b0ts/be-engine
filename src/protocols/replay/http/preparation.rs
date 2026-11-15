//! Native HTTP Source membership and ordered finite response references.
use super::*;
use crate::replay::{PreparedProtocol, RunSequenceReference};

pub(crate) fn prepare_case(
    candidates: &mut candidates::Candidates,
    exchanges: &[ReplayHttpExchange],
    case: &str,
) -> PreparedProtocol {
    let members = candidates.case_members(case);
    candidates.register_exempt(
        exchanges,
        members
            .iter()
            .copied()
            .filter(|index| exchanges[*index].recorded_sequence().is_none()),
    );
    let sequence = members
        .iter()
        .filter_map(|index| Some((*index, exchanges.get(*index)?.recorded_sequence()?)))
        .collect::<Vec<_>>()
        .into();
    PreparedProtocol { members, sequence }
}

pub(crate) fn prepare_run_sequence(
    candidates: &mut candidates::Candidates,
    exchanges: &[ReplayHttpExchange],
) -> Result<Vec<RunSequenceReference>> {
    candidates.register_exempt(
        exchanges,
        exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.run_owned() && exchange.recorded_sequence().is_none())
            .map(|(index, _)| index),
    );
    exchanges
        .iter()
        .enumerate()
        .filter_map(|(index, exchange)| {
            let sequence = exchange.run_sequence()?;
            Some((|| {
                Ok(RunSequenceReference {
                    index,
                    sequence,
                    owner: exchange
                        .recorded_owner()
                        .context("HTTP run dependency owner absent")?,
                })
            })())
        })
        .collect()
}
