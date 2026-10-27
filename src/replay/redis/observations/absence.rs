//! An absent-state lifetime is owned by successful single-key deletion boundaries.
//! Historical reads remain finite; no writer, expiry or future epoch supplies nil.
use super::*;

#[cfg(test)]
mod recorded_tests;
#[cfg(test)]
mod tests;

/// The established absent state has no conflicting accesses: later deletions
/// preserve it and observations cannot mutate it. Source validation below and
/// in `source::prepare` still rejects every writer and non-absent observation
/// atomically. Only the initial reset changes the state being proved, so it
/// retains causal fences against every historical and subsequent access.
pub(super) fn validate_causal_order(timeline: &[(usize, &ReplayExchange)]) -> Result<()> {
    let initial = timeline
        .iter()
        .position(|(_, e)| matches!(e.record.command.as_str(), "DEL" | "UNLINK"))
        .context("absent read observations require an owned single-key DEL or UNLINK")?;
    super::source::validate_causal_order(&timeline[..=initial])?;
    let boundary = timeline[initial].1;
    for (_, historical) in &timeline[..initial] {
        super::source::require_causal_order(historical, boundary)?;
    }
    let multiple_lanes = timeline
        .iter()
        .any(|(_, e)| e.record.connection_id != boundary.record.connection_id);
    let mut lanes = BTreeMap::new();
    for (position, (_, exchange)) in timeline.iter().enumerate() {
        if let Some(previous) =
            lanes.insert(exchange.record.connection_id, exchange.record.sequence)
        {
            ensure!(
                previous < exchange.record.sequence,
                "absent observation Source clocks reverse connection={} sequence={} previous={}",
                exchange.record.connection_id,
                exchange.record.sequence,
                previous,
            );
        }
        if multiple_lanes {
            ensure!(
                exchange
                    .record
                    .earliest_start()
                    .zip(exchange.record.timestamp)
                    .is_some_and(|(start, end)| start <= end),
                "concurrent absent observations require complete Source clocks: \
                 connection={} sequence={} start={:?} end={:?}",
                exchange.record.connection_id,
                exchange.record.sequence,
                exchange.record.earliest_start(),
                exchange.record.timestamp,
            );
        }
        if position > initial {
            super::source::require_causal_order(boundary, exchange)?;
        }
    }
    Ok(())
}

pub(super) fn prepare(
    profile: &mut Profile,
    timeline: &mut Vec<(usize, &ReplayExchange)>,
) -> Result<()> {
    let deletion = |exchange: &ReplayExchange| {
        matches!(exchange.record.command.as_str(), "DEL" | "UNLINK")
            && exchange.args == [profile.key.clone()]
    };
    let first = timeline
        .iter()
        .position(|(_, exchange)| deletion(exchange))
        .context("absent read observations require an owned single-key DEL or UNLINK")?;
    ensure!(
        timeline[..first]
            .iter()
            .all(|(_, exchange)| exchange.record.command == "GET"
                && exchange.args == [profile.key.clone()]),
        "historical absent-read prefix must contain only finite single-key GETs"
    );
    ensure!(
        timeline
            .last()
            .is_some_and(|(_, exchange)| deletion(exchange))
            && timeline[first..]
                .iter()
                .filter(|(_, exchange)| deletion(exchange))
                .count()
                >= 2,
        "absent read observations require a closing deletion boundary"
    );
    ensure!(
        timeline[first..]
            .iter()
            .all(|(_, exchange)| deletion(exchange)
                || (exchange.record.command == "GET" && exchange.args == [profile.key.clone()])),
        "absent read observations cannot hide writers, TTL operations or multi-key access"
    );
    profile.finite_prefix = timeline.drain(..first).map(|(index, _)| index).collect();
    Ok(())
}
