//! Carrier-independent value comparison and derived delivery. Source
//! chooses the codec and format; a known contract failure never becomes opaque.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
mod field_composition;

use super::{
    comparison::{self as json, AnchorClocks, Comparison, Field},
    delivery, encoded,
};
use crate::ExecutionContext;
use traffic_contract::rule::{RuleBinding, ValueRule};
use traffic_contract::{
    codec::{CodecPlan, DecodedValue},
    compare::LogicalProjection,
    rule::{FieldContract, TimestampFormat},
    time,
};
use traffic_policy_value::{
    fields::{FieldOrigin, SelectedGlobalField},
    formats::FormatHost,
};

/// Unknown Source bytes remain strict. Recognized Source fixes the codec even
/// if Target is malformed or does not satisfy a declared field format.
pub fn compare<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &[u8],
    target: &[u8],
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if !rules.is_empty() {
        let codec = encoded::prepared_codec(context, rules)?;
        return compare_decoded(
            context,
            &codec.decode(source)?,
            &codec.decode(target)?,
            plan,
            rules,
            clocks,
        );
    }
    let Some(codec) =
        CodecPlan::try_recognize(source, &traffic_value::Value::Null, context.codecs)?
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
    compare_decoded(context, &source_value, &target_value, plan, rules, clocks)
}

pub fn compare_decoded<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_decoded_with_time_copies(context, source, target, plan, rules, clocks, &[])
}

pub fn compare_decoded_with_time_copies<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
) -> Result<Comparison> {
    if plan.fields().is_empty()
        && rules.is_empty()
        && source.logical_comparison_view(&[]) == target.logical_comparison_view(&[])
    {
        return Ok(Comparison::default());
    }
    compare_decoded_selected(context, source, target, plan, rules, clocks, copies)
}

/// Preflight must inventory semantic Source witnesses even when its immutable
/// Source self-comparison is exact. Ordinary replay retains the exact fast path.
pub fn compare_source_coverage<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &[u8],
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    if !rules.is_empty() {
        let codec = encoded::prepared_codec(context, rules)?;
        return compare_decoded_source_coverage(
            context,
            &codec.decode(source)?,
            plan,
            rules,
            clocks,
        );
    }
    let Some(codec) =
        CodecPlan::try_recognize(source, &traffic_value::Value::Null, context.codecs)?
    else {
        return compare(context, source, source, plan, rules, clocks);
    };
    let decoded = codec.decode(source)?;
    compare_decoded_source_coverage(context, &decoded, plan, rules, clocks)
}

pub fn compare_decoded_source_coverage<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_decoded_selected(context, source, source, plan, rules, clocks, &[])
}

fn compare_decoded_selected<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    target: &DecodedValue,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
) -> Result<Comparison> {
    let protocols = traffic_policy_value::formats::checks(plan, &source.logical)?;
    let verified = protocols.fields();
    let selected = retain_automatic_fields(
        context,
        &source.logical,
        plan.field_plan()
            .selected_value_fields_with_clocks(source.value(), clocks)?,
        rules,
    )?;
    let mut paths = encoded::comparison_paths(&source.logical, rules)?;
    paths.extend(selected.iter().map(|field| field.pointer.clone()));
    paths.extend(verified.iter().map(|field| field.pointer.to_owned()));
    let source_view = source.logical_comparison_view(&paths);
    let target_view = target.logical_comparison_view(&paths);
    let fields = comparison_fields(&source.logical, &selected, rules);
    let mut comparison = json::compare_values(
        context,
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

pub fn compare_logical<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    target: &Value,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_logical_with_time_copies(context, source, target, plan, rules, clocks, &[])
}

pub fn compare_logical_with_time_copies<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    target: &Value,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
) -> Result<Comparison> {
    if plan.fields().is_empty() && rules.is_empty() && source == target {
        return Ok(Comparison::default());
    }
    let selected = selected_fields(context, source, plan, rules, clocks)?;
    let protocols = traffic_policy_value::formats::checks(plan, source)?;
    compare_selected_with_time_copies(
        context,
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
pub fn policy_paths(
    source: &traffic_value::Value,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<Vec<String>> {
    let (paths, _) = prepare_fields(source, plan, clocks)?;
    Ok(paths)
}

pub fn prepare_fields(
    source: &traffic_value::Value,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<(Vec<String>, Vec<SelectedGlobalField>)> {
    let prepared = prepare_projected_fields(&LogicalProjection::new(source)?, plan, clocks)?;
    Ok((prepared.paths, prepared.selected))
}

pub struct PreparedGlobalFields {
    pub paths: Vec<String>,
    pub selected: Vec<SelectedGlobalField>,
    pub clock_independent: bool,
}

pub fn prepare_projected_fields(
    source: &LogicalProjection<'_>,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<PreparedGlobalFields> {
    let selected = plan.field_plan().select_projected_fields(source, clocks)?;
    let native = traffic_policy_value::formats::checks(plan, source.json())?;
    let paths = selected
        .iter()
        .map(|field| field.pointer.clone())
        .chain(native.pointers().map(str::to_owned))
        .collect();
    let clock_independent = native.clock_independent()
        && selected.iter().all(|field| {
            matches!(
                field.contract,
                FieldContract::Exact
                    | FieldContract::Identity { .. }
                    | FieldContract::IdentityAnchor
                    | FieldContract::Unordered
            )
        });
    Ok(PreparedGlobalFields {
        paths,
        selected,
        clock_independent,
    })
}

pub fn compare_fields(
    context: &ExecutionContext<'_>,
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    plan: &dyn FormatHost,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_projected_fields(
        context,
        &LogicalProjection::new(source)?,
        target,
        plan,
        fields,
        None,
        clocks,
    )
}

pub fn compare_prepared_fields(
    context: &ExecutionContext<'_>,
    source: &traffic_value::Value,
    target: &traffic_value::Value,
    plan: &dyn FormatHost,
    fields: &[Field<'_>],
    selected: &[SelectedGlobalField],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_projected_fields(
        context,
        &LogicalProjection::new(source)?,
        target,
        plan,
        fields,
        Some(selected),
        clocks,
    )
}

pub fn compare_projected_fields(
    context: &ExecutionContext<'_>,
    source: &LogicalProjection<'_>,
    target: &traffic_value::Value,
    plan: &dyn FormatHost,
    fields: &[Field<'_>],
    selected: Option<&[SelectedGlobalField]>,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let live_selection;
    let selected = match selected {
        Some(selected) => selected,
        None => {
            live_selection = plan.field_plan().select_projected_fields(source, clocks)?;
            &live_selection
        }
    };
    let native = traffic_policy_value::formats::checks(plan, source.json())?;
    let fields = field_composition::append(source.json(), fields.to_vec(), selected);
    let mut compared = traffic_contract::compare::compare_projected_logical_all(
        source,
        target,
        &fields,
        &[],
        &native.fields(),
        clocks,
        &[],
        context.metadata,
    );
    compared
        .evaluated
        .extend(selected.iter().map(|field| field.rule_id.into()));
    Ok(compared)
}

/// Reuse the ordinary strict remainder and authored owners with independently
/// checked diagnostic leaves, without serializing or cloning the payload.
pub fn compare_logical_with_verified(
    context: &ExecutionContext<'_>,
    source: &Value,
    target: &Value,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
    additional: &[json::VerifiedField<'_>],
) -> Result<Comparison> {
    let selected = selected_fields::<RuleBinding<'_>>(context, source, plan, &[], clocks)?;
    let protocols = traffic_policy_value::formats::checks(plan, source)?;
    let mut verified = protocols.fields();
    verified.extend(additional.iter().map(|field| json::VerifiedField {
        rule_id: field.rule_id,
        pointer: field.pointer,
        verifier: field.verifier,
    }));
    compare_selected_with_time_copies::<RuleBinding<'_>>(
        context,
        source,
        target,
        &selected,
        &[],
        clocks,
        &[],
        &verified,
    )
}

fn compare_selected<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    target: &Value,
    selected: &[SelectedGlobalField],
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_selected_with_time_copies(context, source, target, selected, rules, clocks, &[], &[])
}

#[allow(clippy::too_many_arguments)] // One comparison retains field ownership, clocks and copy proofs.
fn compare_selected_with_time_copies<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    target: &Value,
    selected: &[SelectedGlobalField],
    rules: &[&R],
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
    verified: &[json::VerifiedField<'_>],
) -> Result<Comparison> {
    let fields = comparison_fields(source, selected, rules);
    let mut comparison = json::compare_with_verified_time_copies(
        context, source, target, &fields, verified, clocks, copies,
    );
    comparison
        .evaluated
        .extend(selected.iter().map(|field| field.rule_id.into()));
    Ok(comparison)
}

fn comparison_fields<'a, R: ValueRule + ?Sized>(
    source: &Value,
    selected: &'a [SelectedGlobalField],
    rules: &[&'a R],
) -> Vec<Field<'a>> {
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
    field_composition::append(source, fields, selected)
}

pub fn materialize<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &[u8],
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    if !rules.is_empty() {
        let codec = encoded::prepared_codec(context, rules)?;
        return materialize_decoded(context, &codec.decode(source)?, plan, rules, clocks);
    }
    let Some(codec) =
        CodecPlan::try_recognize(source, &traffic_value::Value::Null, context.codecs)?
    else {
        return Ok(source.to_vec());
    };
    let decoded = codec.decode(source)?;
    materialize_decoded(context, &decoded, plan, rules, clocks)
}

pub fn materialize_decoded<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &DecodedValue,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Vec<u8>> {
    if plan.fields().is_empty() && rules.is_empty() {
        return Ok(source.original_bytes().to_vec());
    }
    let selected = plan
        .field_plan()
        .selected_delivery_fields_with_clocks(&source.logical, clocks)?;
    let result = materialize_selected(context, &source.logical, &selected, rules, clocks)?;
    let mut allowed = rules
        .iter()
        .flat_map(|rule| rule.binding().delivery_time.keys().cloned())
        .collect::<Vec<_>>();
    allowed.extend(
        selected
            .iter()
            .filter(|field| field.contract.time().is_some())
            .map(|field| field.pointer.clone()),
    );
    source.encode(&result, &allowed)
}

pub fn materialize_logical<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Value> {
    if plan.fields().is_empty() && rules.is_empty() {
        return Ok(source.clone());
    }
    materialize_selected(
        context,
        source,
        &plan
            .field_plan()
            .selected_delivery_fields_with_clocks(source, clocks)?,
        rules,
        clocks,
    )
}

/// Translate authored time fields that no earlier delivery rule changed.
pub fn translate_times(
    context: &ExecutionContext<'_>,
    source: &Value,
    delivered: &mut Value,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<()> {
    let mut document = std::borrow::Cow::Owned(std::mem::take(delivered));
    let result = translate_times_cow(context, source, &mut document, plan, clocks);
    *delivered = document.into_owned();
    result
}

pub fn translate_times_cow(
    context: &ExecutionContext<'_>,
    source: &Value,
    delivered: &mut std::borrow::Cow<'_, Value>,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<()> {
    let Some(selected) = time_delivery_fields(context, source, plan, clocks)? else {
        return Ok(());
    };
    translate_selected_times(context, source, delivered, &selected, clocks)
}

pub fn translate_selected_times(
    context: &ExecutionContext<'_>,
    source: &Value,
    delivered: &mut std::borrow::Cow<'_, Value>,
    selected: &[SelectedGlobalField],
    clocks: AnchorClocks,
) -> Result<()> {
    let timed = materialize_selected::<RuleBinding<'_>>(context, source, selected, &[], clocks)?;
    if matches!(delivered, std::borrow::Cow::Borrowed(original) if std::ptr::eq(*original, source))
    {
        *delivered = std::borrow::Cow::Owned(timed);
        return Ok(());
    }
    for field in selected {
        let pointer = &field.pointer;
        if source.pointer(pointer) == delivered.pointer(pointer) {
            *delivered
                .to_mut()
                .pointer_mut(pointer)
                .context("global time delivery field disappeared")? = timed
                .pointer(pointer)
                .context("global time delivery value disappeared")?
                .clone();
        }
    }
    Ok(())
}

/// Resolve authored time delivery against the Source clock before Replay reaches it.
/// `None` proves that even a different Target clock cannot require this translation.
pub fn time_delivery_fields(
    context: &ExecutionContext<'_>,
    source: &Value,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<Option<Vec<SelectedGlobalField>>> {
    if plan.fields().is_empty() {
        return Ok(None);
    }
    let mut selected = plan
        .field_plan()
        .selected_delivery_fields_with_clocks(source, clocks)?;
    selected.retain(|field| field.contract.time().is_some());
    if selected.is_empty()
        && traffic_contract::compare::compare_all(
            source,
            source,
            &[],
            &[],
            &[],
            clocks,
            &[],
            context.metadata,
        )
        .passed()
    {
        return Ok(None);
    }
    Ok(Some(selected))
}

fn materialize_selected<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    selected: &[SelectedGlobalField],
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Value> {
    let mut result = delivery::materialize(context, source, rules, clocks)?;
    let times = selected
        .iter()
        .filter_map(|field| field.contract.time().map(|time| (&field.pointer, time)))
        .collect::<Vec<_>>();
    for (pointer, contract) in &times {
        // Existing scoped delivery owns its selected field. Translate once,
        // then validate the combined declarations against the final copy.
        if rules.iter().any(|rule| {
            rule.binding().delivery_time.keys().any(|pattern| {
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
    let check = compare_selected(context, source, &result, &writable, rules, clocks)?;
    ensure!(
        check.passed(),
        "derived global JSON response violates its contracts: {:?}",
        check.differences
    );
    Ok(result)
}

fn selected_fields<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    plan: &dyn FormatHost,
    rules: &[&R],
    clocks: AnchorClocks,
) -> Result<Vec<SelectedGlobalField>> {
    retain_automatic_fields(
        context,
        source,
        plan.field_plan()
            .selected_fields_with_clocks(source, clocks)?,
        rules,
    )
}

fn retain_automatic_fields<R: ValueRule + ?Sized>(
    context: &ExecutionContext<'_>,
    source: &Value,
    mut selected: Vec<SelectedGlobalField>,
    rules: &[&R],
) -> Result<Vec<SelectedGlobalField>> {
    if rules.is_empty() {
        return Ok(selected);
    }
    let mut owned = Vec::new();
    for rule in rules {
        for (pattern, contract) in rule.binding().fields {
            // Composite policies retain inference at descendant locations.
            // A direct field owner decides the complete selected value.
            if !contract.supports_child_rules(context.metadata.policies())? {
                owned.extend(delivery::select(pattern, source)?);
            }
        }
    }
    selected.retain(|field| {
        field.origin != FieldOrigin::Inferred
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

/// Retain Source field patterns while projecting bounded delivered-value provenance.
pub fn time_leaves(
    source: &Value,
    plan: &dyn FormatHost,
    clocks: AnchorClocks,
) -> Result<Vec<traffic_contract::provenance::TimeCopyLeaf>> {
    use traffic_contract::provenance::{MAX_CASE_COPIES, TimeCopyLeaf};
    let mut output = Vec::new();
    for selected in plan
        .field_plan()
        .selected_fields_with_clocks(source, clocks)?
    {
        let pointer = selected.pointer;
        let Some(value) = source.pointer(&pointer) else {
            continue;
        };
        let Some(time) = selected.contract.time() else {
            continue;
        };
        traffic_contract::compare::parse_time_pair(value, value, &time)?;
        output.push(TimeCopyLeaf {
            rule_id: selected.rule_id,
            pattern: selected.pattern,
            pointer,
            value: value.clone(),
            time,
        });
        ensure!(
            output.len() <= MAX_CASE_COPIES,
            "global time copy leaf enumeration exceeds its bound"
        );
    }
    Ok(output)
}
