//! Carrier-independent value comparison and derived delivery. Source
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
    policy::{CompiledJsonPolicy, CompiledRule, SelectedGlobalField, TimestampFormat},
    value_codec::DecodedValue,
};

/// Unknown Source bytes remain strict. Recognized Source fixes the codec even
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
    if let Ok(source) = crate::value_codec::sse::Document::decode(source) {
        let target = crate::value_codec::sse::Document::decode(target)
            .context("Target payload changed from Source SSE encoding")?;
        return crate::value_codec::sse::compare(&source, &target, plan, clocks);
    }
    let Some(codec) = crate::value_codec::try_recognize(source, &traffic_value::Value::Null)?
    else {
        let differences = if source == target {
            vec![]
        } else {
            vec![json::Difference {
                pointer: String::new(),
                reason: "opaque payload bytes changed".into(),
            }]
        };
        return Ok(Comparison {
            differences,
            ..Default::default()
        });
    };
    let source_value = codec.decode(source)?;
    let target_value = codec
        .decode(target)
        .context("Target payload violates the Source content codec")?;
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
        && source.logical_comparison_view(&[]) == target.logical_comparison_view(&[])
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
    if crate::value_codec::sse::Document::decode(source).is_ok() {
        return compare(source, source, plan, rules, clocks);
    }
    let Some(codec) = crate::value_codec::try_recognize(source, &traffic_value::Value::Null)?
    else {
        return compare(source, source, plan, rules, clocks);
    };
    let decoded = codec.decode(source)?;
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
    let selected = retain_automatic_fields(
        &source.logical,
        plan.selected_value_fields_with_clocks(source.value(), clocks)?,
        rules,
    )?;
    let mut paths = encoded::comparison_paths(&source.logical, rules)?;
    paths.extend(selected.iter().map(|field| field.pointer.clone()));
    paths.extend(verified.iter().map(|field| field.pointer.to_owned()));
    let source_view = source.logical_comparison_view(&paths);
    let target_view = target.logical_comparison_view(&paths);
    let fields = comparison_fields(&source.logical, &selected, rules);
    let mut comparison = json::compare_values(
        &source_view,
        &target_view,
        &fields,
        &verified,
        clocks,
        copies,
    );
    comparison
        .evaluated
        .extend(selected.iter().map(|field| field.rule_id.into()));
    Ok(comparison)
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

/// The same global fields and native leaf checks compose over any decoded carrier.
pub(crate) fn policy_paths(
    source: &traffic_value::Value,
    plan: &CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<Vec<String>> {
    let selected = plan.selected_value_fields_with_clocks(source, clocks)?;
    let projection = serde_json::to_value(source)?;
    let native = super::global_protocol::checks(plan, &projection)?;
    Ok(selected
        .into_iter()
        .map(|field| field.pointer)
        .chain(native.fields().iter().map(|field| field.pointer.to_owned()))
        .collect())
}

pub(crate) fn compare_fields(
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    plan: &CompiledJsonPolicy,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let projection = serde_json::to_value(source)?;
    let selected = plan.selected_value_fields_with_clocks(source, clocks)?;
    let native = super::global_protocol::checks(plan, &projection)?;
    let fields = field_composition::append(&projection, fields.to_vec(), &selected);
    let mut compared = traffic_contract::compare::compare_logical_all(
        source,
        target,
        &fields,
        &[],
        &native.fields(),
        clocks,
        &[],
        &json::PolicyMetadata,
    );
    compared
        .evaluated
        .extend(selected.iter().map(|field| field.rule_id.into()));
    Ok(compared)
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
    let fields = comparison_fields(source, selected, rules);
    let mut comparison =
        json::compare_with_verified_time_copies(source, target, &fields, verified, clocks, copies);
    comparison
        .evaluated
        .extend(selected.iter().map(|field| field.rule_id.into()));
    Ok(comparison)
}

fn comparison_fields<'a>(
    source: &Value,
    selected: &'a [SelectedGlobalField],
    rules: &[&'a CompiledRule],
) -> Vec<Field<'a>> {
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
    field_composition::append(source, fields, selected)
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
    let Some(codec) = crate::value_codec::try_recognize(source, &traffic_value::Value::Null)?
    else {
        return Ok(source.to_vec());
    };
    let decoded = codec.decode(source)?;
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
    retain_automatic_fields(
        source,
        plan.selected_fields_with_clocks(source, clocks)?,
        rules,
    )
}

fn retain_automatic_fields(
    source: &Value,
    mut selected: Vec<SelectedGlobalField>,
    rules: &[&CompiledRule],
) -> Result<Vec<SelectedGlobalField>> {
    if rules.is_empty() {
        return Ok(selected);
    }
    let mut owned = Vec::new();
    for rule in rules {
        for (pattern, contract) in &rule.rule.contract {
            // Unordered authorizes array pairing; its scalar descendants still
            // retain their ordinary standard timestamp semantics.
            if !contract.supports_child_rules(traffic_extensions::policies())? {
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
