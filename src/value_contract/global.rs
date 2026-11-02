//! Carrier-independent global JSON comparison and derived delivery. Source
//! chooses the codec and format; a known contract failure never becomes opaque.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
mod field_composition;

use super::{
    delivery, encoded,
    json::{self, AnchorClocks, Comparison, Field},
    time,
};
#[cfg(test)]
use crate::policy::GLOBAL_JSON_ID;
use crate::{
    policy::{
        Codec, CompiledJsonPolicy, CompiledRule, FieldContract, SelectedGlobalField,
        TimestampFormat,
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
    if plan.fields.is_empty()
        && rules.is_empty()
        && source.comparison_view(&[]) == target.comparison_view(&[])
    {
        return Ok(Comparison::default());
    }
    compare_decoded_selected(source, target, plan, rules, clocks, copies)
}

/// Preflight must inventory semantic Source witnesses even when its immutable
/// Source self-comparison is exact. Ordinary replay retains the exact fast path.
pub(crate) fn compare_source_coverage(
    source: &[u8],
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if !rules.is_empty() {
        let codec = encoded::prepared_codec(rules)?;
        return compare_decoded_source_coverage(&codec.decode(source)?, plan, rules, clocks);
    }
    let Ok(decoded) = CodecView::decode(&Codec::Json, source) else {
        return compare(source, source, plan, rules, clocks);
    };
    compare_decoded_source_coverage(&decoded, plan, rules, clocks)
}

pub(crate) fn compare_decoded_source_coverage(
    source: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_decoded_selected(source, source, plan, rules, clocks, &[])
}

fn compare_decoded_selected(
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
) -> Result<Comparison> {
    let protocols = super::global_protocol::checks(plan, &source.logical)?;
    let verified = protocols.fields();
    let selected = selected_fields(&source.logical, plan, rules, clocks)?;
    let mut paths = encoded::comparison_paths(&source.logical, rules)?;
    paths.extend(selected.iter().map(|field| field.pointer.clone()));
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
    if plan.fields.is_empty() && rules.is_empty() && source == target {
        return Ok(Comparison::default());
    }
    let selected = selected_fields(source, plan, rules, clocks)?;
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

/// Reuse the ordinary strict remainder and authored owners with independently
/// checked diagnostic leaves, without serializing or cloning the payload.
pub(crate) fn compare_logical_with_verified(
    source: &Value,
    target: &Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
    additional: &[json::VerifiedField<'_>],
) -> Result<Comparison> {
    let selected = selected_fields(source, plan, &[], clocks)?;
    let protocols = super::global_protocol::checks(plan, source)?;
    let mut verified = protocols.fields();
    verified.extend(additional.iter().map(|field| json::VerifiedField {
        rule_id: field.rule_id,
        pointer: field.pointer,
        verifier: field.verifier,
    }));
    compare_selected_with_time_copies(source, target, &selected, &[], clocks, &[], &verified)
}

fn compare_selected(
    source: &Value,
    target: &Value,
    selected: &[SelectedGlobalField],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_selected_with_time_copies(source, target, selected, rules, clocks, &[], &[])
}

fn compare_selected_with_time_copies(
    source: &Value,
    target: &Value,
    selected: &[SelectedGlobalField],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: &[json::VerifiedTimeCopy],
    verified: &[json::VerifiedField<'_>],
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
    let fields = field_composition::append(source, fields, selected);
    let mut comparison =
        json::compare_with_verified_time_copies(source, target, &fields, verified, clocks, copies);
    comparison
        .evaluated
        .extend(selected.iter().map(|field| field.rule_id.into()));
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
    if plan.fields.is_empty() && rules.is_empty() {
        return Ok(source.original_bytes().to_vec());
    }
    let selected = plan.selected_delivery_fields_with_clocks(&source.logical, clocks)?;
    let result = materialize_selected(&source.logical, &selected, rules, clocks)?;
    let mut allowed = rules
        .iter()
        .flat_map(|rule| rule.delivery_time.keys().cloned())
        .collect::<Vec<_>>();
    allowed.extend(
        selected
            .iter()
            .filter(|field| field.contract.time().is_some())
            .map(|field| field.pointer.clone()),
    );
    source.encode(&result, &allowed)
}

pub(crate) fn materialize_logical(
    source: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    if plan.fields.is_empty() && rules.is_empty() {
        return Ok(source.clone());
    }
    materialize_selected(
        source,
        &plan.selected_delivery_fields_with_clocks(source, clocks)?,
        rules,
        clocks,
    )
}

fn materialize_selected(
    source: &Value,
    selected: &[SelectedGlobalField],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    let mut result = delivery::materialize(source, rules, clocks)?;
    let times = selected
        .iter()
        .filter_map(|field| field.contract.time().map(|time| (&field.pointer, time)))
        .collect::<Vec<_>>();
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
                clocks.get(contract.anchor),
            )?
        } else {
            let (a, b) = clocks.get(contract.anchor).require()?;
            let delta = time::date_nanos(b) - time::date_nanos(a);
            let quantum = delivery::value_quantum(original, contract.format);
            delivery::shift(original, contract, delta / quantum * quantum)?
        };
        *result
            .pointer_mut(pointer)
            .context("global delivery field disappeared")? = translated;
    }
    let writable = selected
        .iter()
        .filter(|field| field.contract.time().is_some())
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

fn selected_fields(
    source: &Value,
    plan: &CompiledJsonPolicy,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Vec<SelectedGlobalField>> {
    let mut selected = plan.selected_fields_with_clocks(source, clocks)?;
    if rules.is_empty() {
        return Ok(selected);
    }
    let mut owned = Vec::new();
    for rule in rules {
        for (pattern, contract) in &rule.rule.contract {
            // Unordered authorizes array pairing; its scalar descendants still
            // retain their ordinary standard timestamp semantics.
            if !matches!(contract, FieldContract::Unordered) {
                owned.extend(delivery::select(pattern, source)?);
            }
        }
    }
    selected.retain(|field| {
        field.rule_id != time::automatic::RULE_ID
            || !owned.iter().any(|owner| {
                field.pointer == *owner
                    || field
                        .pointer
                        .strip_prefix(owner)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
    });
    Ok(selected)
}

#[cfg(test)]
mod tests;
