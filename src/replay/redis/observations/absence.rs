//! An absent-state lifetime is owned by successful single-key deletion boundaries.
//! Historical reads remain finite; no writer, expiry or future epoch supplies nil.
use super::*;

#[cfg(test)]
mod recorded_tests;
#[cfg(test)]
mod tests;

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
