//! Pure typed-codec comparison shared by Replay and evidence preflight.
use crate::{
    policy::{Codec, CompiledRule},
    value_codec::{CodecPlan, DecodedValue},
    value_contract::json::{self, AnchorClocks, Comparison, Field},
};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;
mod prepared;
#[cfg(test)]
mod tests;

pub(crate) fn merged_codec(rules: &[&CompiledRule]) -> Result<Codec> {
    let mut codec = rules
        .first()
        .context("value comparison requires selected rules")?
        .rule
        .codec
        .clone();
    for rule in rules.iter().skip(1) {
        merge_codec(&mut codec, &rule.rule.codec)?;
    }
    Ok(codec)
}

/// Common carriers reuse their load-time plan without cloning PB schemas.
/// Different overlapping PB declarations merge once for the selected group.
pub(crate) fn prepared_codec(rules: &[&CompiledRule]) -> Result<Arc<CodecPlan>> {
    prepared::codec(rules)
}

pub(crate) fn compare(
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let codec = prepared_codec(rules)?;
    let source = codec.decode(source)?;
    let target = codec.decode(target)?;
    compare_decoded(&source, &target, rules, clocks)
}

/// Reuse immutable decoded evidence, while evaluating permissions, conditions
/// and independently supplied clocks afresh for this comparison.
pub(crate) fn compare_decoded(
    source: &DecodedValue,
    target: &DecodedValue,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_decoded_with_time_copies(source, target, rules, clocks, &[])
}

pub(crate) fn compare_decoded_with_time_copies(
    source: &DecodedValue,
    target: &DecodedValue,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
) -> Result<Comparison> {
    ensure!(
        source.view().kind() == target.view().kind(),
        "compared values use different payload codecs"
    );
    let fields = rules
        .iter()
        .flat_map(|rule| {
            rule.rule
                .contract
                .iter()
                .map(move |(pointer, contract)| Field {
                    rule_id: &rule.rule.id,
                    pointer,
                    contract,
                })
        })
        .collect::<Vec<_>>();
    let source_view =
        source.logical_comparison_view(&comparison_paths(source.view().logical(), rules)?);
    if std::ptr::eq(source, target) {
        return Ok(json::compare_values(
            &source_view,
            &source_view,
            &fields,
            &[],
            clocks,
            copies,
        ));
    }
    let target_view =
        target.logical_comparison_view(&comparison_paths(target.view().logical(), rules)?);
    Ok(json::compare_values(
        &source_view,
        &target_view,
        &fields,
        &[],
        clocks,
        copies,
    ))
}

/// Retain native PB wire identity for every inactive field. The actual field
/// permission is still evaluated against immutable Source by the comparator.
pub(crate) fn comparison_paths(
    root: &serde_json::Value,
    rules: &[&CompiledRule],
) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for rule in rules {
        for (pointer, contract) in &rule.rule.contract {
            if let crate::policy::FieldContract::Conditional { when, .. } = contract {
                for selected in super::delivery::select(pointer, root)? {
                    if when.active(root, &selected)? {
                        paths.push(selected);
                    }
                }
            } else {
                paths.push(pointer.clone());
            }
        }
    }
    Ok(paths)
}

pub(crate) fn merge_codec(codec: &mut Codec, next: &Codec) -> Result<()> {
    if codec == next {
        return Ok(());
    }
    ensure!(
        codec.id() == next.id(),
        "selected rules disagree on the payload codec"
    );
    let left = serde_json::from_value(codec.configuration().clone())?;
    let right = serde_json::from_value(next.configuration().clone())?;
    let configuration = traffic_extensions::codecs().merge(codec.id(), &[&left, &right])?;
    *codec = Codec::registered(codec.id().to_owned(), serde_json::to_value(configuration)?)?;
    Ok(())
}
