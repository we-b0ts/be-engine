//! Pure typed-codec comparison shared by Replay and evidence preflight.
use crate::{ExecutionContext, comparison as json};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;
use traffic_contract::{codec::Codec, rule::ValueRule};
use traffic_contract::{
    codec::{CodecPlan, DecodedValue},
    compare::{AnchorClocks, Comparison, Field},
};
pub mod prepared;

pub fn merged_codec<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    rules: &[&R],
) -> Result<Codec> {
    let mut codec = rules
        .first()
        .context("value comparison requires selected rules")?
        .binding()
        .codec
        .clone();
    for rule in rules.iter().skip(1) {
        merge_codec(context, &mut codec, rule.binding().codec)?;
    }
    Ok(codec)
}

/// Common carriers reuse their load-time plan without cloning PB schemas.
/// Different overlapping PB declarations merge once for the selected group.
pub fn prepared_codec<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    rules: &[&R],
) -> Result<Arc<CodecPlan>> {
    prepared::codec(context, rules)
}

pub fn compare<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &[u8],
    target: &[u8],
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let codec = prepared_codec(context, rules)?;
    let source = codec.decode(source)?;
    let target = codec.decode(target)?;
    compare_decoded(context, &source, &target, rules, clocks)
}

/// Reuse immutable decoded evidence, while evaluating permissions, conditions
/// and independently supplied clocks afresh for this comparison.
pub fn compare_decoded<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    target: &DecodedValue,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_decoded_with_time_copies(context, source, target, rules, clocks, &[])
}

pub fn compare_decoded_with_time_copies<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    target: &DecodedValue,
    rules: &[&R],
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
) -> Result<Comparison> {
    ensure!(
        source.view().kind() == target.view().kind(),
        "compared values use different payload codecs"
    );
    let fields = rules
        .iter()
        .flat_map(|rule| {
            rule.binding()
                .fields
                .iter()
                .map(move |(pointer, contract)| Field {
                    rule_id: rule.binding().id,
                    pointer,
                    contract,
                })
        })
        .collect::<Vec<_>>();
    let source_view =
        source.logical_comparison_view(&comparison_paths(source.view().logical(), rules)?);
    if std::ptr::eq(source, target) {
        return Ok(json::compare_values(
            context,
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
        context,
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
pub fn comparison_paths<R: ValueRule + ?Sized>(
    root: &serde_json::Value,
    rules: &[&R],
) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for rule in rules {
        for (pointer, contract) in rule.binding().fields {
            if let traffic_contract::rule::FieldContract::Conditional { when, .. } = contract {
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

pub fn merge_codec(context: &ExecutionContext<'_>, codec: &mut Codec, next: &Codec) -> Result<()> {
    if codec == next {
        return Ok(());
    }
    ensure!(
        codec.id() == next.id(),
        "selected rules disagree on the payload codec"
    );
    let left = serde_json::from_value(codec.configuration().clone())?;
    let right = serde_json::from_value(next.configuration().clone())?;
    let configuration = context.codecs.merge(codec.id(), &[&left, &right])?;
    *codec = Codec::registered(codec.id().to_owned(), serde_json::to_value(configuration)?)?;
    Ok(())
}
