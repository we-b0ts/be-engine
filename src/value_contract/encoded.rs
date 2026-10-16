//! Pure typed-codec comparison shared by Replay and evidence preflight.
use crate::{
    policy::{Codec, CompiledRule},
    value_codec::CodecView,
    value_contract::json::{self, AnchorClocks, Comparison, Field},
};
use anyhow::{Context, Result, ensure};

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
        match (&mut codec, &rule.rule.codec) {
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
    let paths = rules
        .iter()
        .flat_map(|rule| rule.rule.contract.keys().cloned())
        .collect::<Vec<_>>();
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
        &source.comparison_value(&paths),
        &target.comparison_value(&paths),
        &fields,
        clocks,
    ))
}
