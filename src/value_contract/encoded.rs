//! Pure typed-codec comparison shared by Replay and evidence preflight.
use crate::{
    policy::{Codec, CompiledRule},
    value_codec::{CodecPlan, DecodedValue},
    value_contract::json::{self, AnchorClocks, Comparison, Field},
};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;
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
    let first = rules
        .first()
        .context("value comparison requires selected rules")?;
    if rules.iter().all(|rule| rule.rule.codec == first.rule.codec) {
        return Ok(Arc::clone(&first.codec_plan));
    }
    Ok(Arc::new(CodecPlan::compile(&merged_codec(rules)?)?))
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
    let source_view = source.comparison_view(&comparison_paths(&source.logical, rules)?);
    if std::ptr::eq(source, target) {
        return Ok(json::compare_with_time_copies(
            &source_view,
            &source_view,
            &fields,
            clocks,
            copies,
        ));
    }
    let target_view = target.comparison_view(&comparison_paths(&target.logical, rules)?);
    Ok(json::compare_with_time_copies(
        &source_view,
        &target_view,
        &fields,
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
    match (codec, next) {
        (Codec::Json, Codec::Json) | (Codec::Scalar, Codec::Scalar) => (),
        (Codec::Protobuf(merged), Codec::Protobuf(next)) => {
            for (path, field) in &next.fields {
                if let Some(current) = merged.fields.get(path) {
                    ensure!(
                        current == field,
                        "selected rules disagree on a typed Protobuf field"
                    );
                } else {
                    ensure!(
                        merged
                            .fields
                            .values()
                            .all(|current| current.field_path != field.field_path),
                        "selected rules alias a Protobuf wire field"
                    );
                    merged.fields.insert(path.clone(), field.clone());
                }
            }
        }
        _ => anyhow::bail!("selected rules disagree on the payload codec"),
    }
    Ok(())
}
