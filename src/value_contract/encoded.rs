//! Pure typed-codec comparison shared by Replay and evidence preflight.
use crate::{
    policy::{Codec, CompiledRule},
    value_codec::CodecView,
    value_contract::json::{self, AnchorClocks, Comparison, Field},
};
use anyhow::{Context, Result, ensure};
#[cfg(test)]
mod tests;

pub(crate) fn materialize(
    source: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    let codec = merged_codec(rules)?;
    let decoded = CodecView::decode(&codec, source)?;
    materialize_decoded(&decoded, rules, clocks)
}

pub(crate) fn materialize_decoded(
    decoded: &crate::value_codec::DecodedValue,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    let translated = crate::value_contract::delivery::materialize(&decoded.logical, rules, clocks)?;
    let allowed = rules
        .iter()
        .flat_map(|rule| rule.delivery_time.keys().cloned())
        .collect::<Vec<_>>();
    decoded.encode(&translated, &allowed)
}
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

pub(crate) fn compare(
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let codec = merged_codec(rules)?;
    let source = CodecView::decode(&codec, source)?;
    let target = CodecView::decode(&codec, target)?;
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
    Ok(json::compare(
        &source.comparison_value(&comparison_paths(&source.logical, rules)?),
        &target.comparison_value(&comparison_paths(&target.logical, rules)?),
        &fields,
        clocks,
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
        (Codec::Json, Codec::Json) => (),
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
