//! Carrier-independent global JSON comparison and derived delivery. Source
//! chooses the codec and format; a known contract failure never becomes opaque.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{
    delivery, encoded,
    json::{self, AnchorClocks, Comparison, Field},
    time,
};
use crate::{
    policy::{
        Codec, CompiledJsonPolicy, CompiledRule, FieldContract, GLOBAL_JSON_ID, TimestampFormat,
    },
    value_codec::{CodecView, DecodedValue},
};

/// Unknown Source bytes remain strict. Valid Source JSON fixes the codec even
/// if Target is malformed or does not satisfy a declared field format.
pub(crate) fn compare(
    source: &[u8],
    target: &[u8],
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if !rules.is_empty() {
        let codec = encoded::prepared_codec(rules)?;
        return compare_decoded(
            &codec.decode(source)?,
            &codec.decode(target)?,
            plan,
            rules,
            clocks,
        );
    }
    let Ok(source_value) = CodecView::decode(&Codec::Json, source) else {
        if let Ok(source) = crate::value_codec::sse::Document::decode(source) {
            let target = crate::value_codec::sse::Document::decode(target)
                .context("Target payload changed from Source SSE encoding")?;
            return crate::value_codec::sse::compare(&source, &target, plan, clocks);
        }
        let mut comparison = Comparison::default();
        comparison.differences = if source == target {
            vec![]
        } else {
            vec![json::Difference {
                pointer: String::new(),
                reason: "opaque payload bytes changed".into(),
            }]
        };
        return Ok(comparison);
    };
    let target_value = CodecView::decode(&Codec::Json, target)
        .context("Target payload changed from Source JSON encoding")?;
    compare_decoded(&source_value, &target_value, plan, rules, clocks)
}

pub(crate) fn compare_decoded(
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_decoded_with_time_copies(source, target, plan, rules, clocks, &[])
}

pub(crate) fn compare_decoded_with_time_copies(
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
) -> Result<Comparison> {
    let protocols = super::global_protocol::checks(plan, &source.logical)?;
    let verified = protocols.fields();
    let selected = plan.comparison_fields(&source.logical, &target.logical, clocks)?;
    let mut paths = encoded::comparison_paths(&source.logical, rules)?;
    paths.extend(selected.iter().map(|(pointer, _)| pointer.clone()));
    paths.extend(verified.iter().map(|field| field.pointer.to_owned()));
    let source_view = source.comparison_view(&paths);
    let target_view = target.comparison_view(&paths);
    compare_selected_with_time_copies(
        &source_view,
        &target_view,
        &selected,
        rules,
        clocks,
        copies,
        &verified,
    )
}

#[cfg(test)]
pub(crate) fn compare_logical(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_logical_with_time_copies(source, target, plan, rules, clocks, &[])
}

pub(crate) fn compare_logical_with_time_copies(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
) -> Result<Comparison> {
    let selected = plan.comparison_fields(source, target, clocks)?;
    let protocols = super::global_protocol::checks(plan, source)?;
    compare_selected_with_time_copies(
        source,
        target,
        &selected,
        rules,
        clocks,
        copies,
        &protocols.fields(),
    )
}

fn compare_selected(
    source: &Value,
    target: &Value,
    selected: &[(String, FieldContract)],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_selected_with_time_copies(source, target, selected, rules, clocks, &[], &[])
}

fn compare_selected_with_time_copies(
    source: &Value,
    target: &Value,
    selected: &[(String, FieldContract)],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
    verified: &[json::VerifiedField<'_>],
) -> Result<Comparison> {
    let mut fields = rules
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
    for (pointer, contract) in selected {
        let existing = fields
            .iter()
            .filter(|field| {
                delivery::select(field.pointer, source).is_ok_and(|paths| paths.contains(pointer))
            })
            .collect::<Vec<_>>();
        // Compatible contextual clocks compose in the ordinary comparator.
        // An identical non-time declaration has only one semantic owner at the
        // leaf, while both declaration IDs retain evaluated evidence below.
        let duplicate =
            !existing.is_empty() && existing.iter().all(|field| field.contract == contract);
        if !duplicate {
            fields.push(Field {
                rule_id: GLOBAL_JSON_ID,
                pointer,
                contract,
            });
        }
    }
    let mut comparison =
        json::compare_with_verified_time_copies(source, target, &fields, verified, clocks, copies);
    if !selected.is_empty() {
        comparison.evaluated.insert(GLOBAL_JSON_ID.into());
    }
    Ok(comparison)
}

#[cfg(test)]
pub(crate) fn materialize(
    source: &[u8],
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    if !rules.is_empty() {
        let codec = encoded::prepared_codec(rules)?;
        return materialize_decoded(&codec.decode(source)?, plan, rules, clocks);
    }
    let Ok(decoded) = CodecView::decode(&Codec::Json, source) else {
        return Ok(source.to_vec());
    };
    materialize_decoded(&decoded, plan, rules, clocks)
}

pub(crate) fn materialize_decoded(
    source: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    let selected = plan.fields_with_clocks(&source.logical, clocks)?;
    let result = materialize_selected(&source.logical, &selected, rules, clocks)?;
    let mut allowed = rules
        .iter()
        .flat_map(|rule| rule.delivery_time.keys().cloned())
        .collect::<Vec<_>>();
    allowed.extend(
        selected
            .iter()
            .filter(|(_, contract)| contract.time().is_some())
            .map(|(pointer, _)| pointer.clone()),
    );
    source.encode(&result, &allowed)
}

pub(crate) fn materialize_logical(
    source: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    materialize_selected(
        source,
        &plan.fields_with_clocks(source, clocks)?,
        rules,
        clocks,
    )
}

fn materialize_selected(
    source: &Value,
    selected: &[(String, FieldContract)],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    let mut result = delivery::materialize(source, rules, clocks)?;
    let times = selected
        .iter()
        .filter_map(|(pointer, contract)| contract.time().map(|time| (pointer, time)))
        .collect::<Vec<_>>();
    let quantum = times
        .iter()
        .map(|(_, contract)| match contract.format {
            TimestampFormat::UnixSeconds | TimestampFormat::AmzDate => 1_000_000_000,
            TimestampFormat::UnixMilliseconds => 1_000_000,
            TimestampFormat::UnixMicroseconds => 1_000,
            _ => 1,
        })
        .max()
        .unwrap_or(1);
    for (pointer, contract) in &times {
        // Existing scoped delivery owns its selected field. Translate once,
        // then validate the combined declarations against the final copy.
        if rules.iter().any(|rule| {
            rule.delivery_time.keys().any(|pattern| {
                delivery::select(pattern, source).is_ok_and(|paths| paths.contains(pointer))
            })
        }) {
            continue;
        }
        let original = source
            .pointer(pointer)
            .context("global delivery field disappeared")?;
        let translated = if contract.format == TimestampFormat::CalendarDate {
            time::calendar::rebase(
                original,
                contract
                    .offset()?
                    .context("calendar_date requires utc_offset")?,
                clocks.dependency,
            )?
        } else {
            let (a, b) = clocks.dependency.require()?;
            let delta = time::date_nanos(b) - time::date_nanos(a);
            delivery::shift(original, contract, delta / quantum * quantum)?
        };
        *result
            .pointer_mut(pointer)
            .context("global delivery field disappeared")? = translated;
    }
    let writable = selected
        .iter()
        .filter(|(_, contract)| contract.time().is_some())
        .cloned()
        .collect::<Vec<_>>();
    let check = compare_selected(source, &result, &writable, rules, clocks)?;
    ensure!(
        check.passed(),
        "derived global JSON response violates its contracts: {:?}",
        check.differences
    );
    Ok(result)
}

#[cfg(test)]
mod tests;
