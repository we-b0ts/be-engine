//! Native temporal provenance projected into the shared copy-proof contract.
use super::*;
pub fn time_leaves(
    selected: &Selection,
    policy: &(impl ValuePolicy + ?Sized),
    clocks: AnchorClocks,
) -> Result<Vec<traffic_contract::provenance::TimeCopyLeaf>> {
    use traffic_contract::provenance::TimeCopyLeaf;
    if selected.id == GLOBAL_JSON_ID {
        return policy
            .document()
            .map(|plan| {
                traffic_policy_execution::global::time_leaves(&selected.source, plan, clocks)
            })
            .transpose()
            .map(Option::unwrap_or_default);
    }
    if selected.date {
        return Ok(vec![TimeCopyLeaf {
            rule_id: selected.id,
            pattern: String::new(),
            pointer: String::new(),
            value: selected.source.clone(),
            time: native_date_time(),
        }]);
    }
    Ok(selected
        .fields
        .iter()
        .filter_map(|(pointer, field)| {
            field.time().and_then(|time| {
                selected.source.pointer(pointer).map(|value| TimeCopyLeaf {
                    rule_id: selected.id,
                    pattern: pointer.clone(),
                    pointer: pointer.clone(),
                    value: value.clone(),
                    time,
                })
            })
        })
        .collect())
}

pub(super) fn native_date_time() -> traffic_contract::rule::TimeContract {
    traffic_contract::rule::TimeContract {
        format: traffic_contract::rule::TimestampFormat::CalendarDate,
        relation: traffic_contract::rule::TimeRelation::PreserveOffset,
        anchor: traffic_contract::rule::TimeAnchor::DependencyRequestStart,
        utc_offset: Some("+00:00".into()),
        clock_group: None,
        clock_scope: traffic_contract::rule::ClockScope::Shared,
    }
}

pub fn compare_selection_with_context(
    selected: &Selection,
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
    policy: &(impl ValuePolicy + ?Sized),
) -> Result<Comparison> {
    if selected.id == GLOBAL_JSON_ID
        && let Some(plan) = policy.document()
    {
        return traffic_policy_execution::global::compare_logical_with_time_copies::<
            dyn traffic_contract::rule::ValueRule,
        >(
            &policy.execution(),
            &selected.source,
            &selected.target,
            plan,
            &[],
            clocks,
            copies,
        );
    }
    compare_selection_with_copies(&policy.execution(), selected, clocks, copies)
}

pub fn compare_selection_with_copies(
    context: &ExecutionContext<'_>,
    selected: &Selection,
    clocks: AnchorClocks,
    copies: &[&dyn json::ValueCopyProof],
) -> Result<Comparison> {
    if selected.source == selected.target
        && selected.id == MYSQL_ID
        && (selected.date
            || selected
                .fields
                .iter()
                .all(|(_, field)| field.time().is_some()))
    {
        let mut result = Comparison::default();
        if selected.date || !selected.fields.is_empty() {
            result.evaluated.insert(MYSQL_ID.into());
        }
        return Ok(result);
    }
    if selected.date {
        let time = serde_json::from_value(serde_json::to_value(native_date_time())?)?;
        if copies.iter().any(|copy| {
            copy.permits_value(MYSQL_ID, "", "", &selected.source, &selected.target, &time)
        }) {
            let mut result = Comparison::default();
            result.evaluated.insert(MYSQL_ID.into());
            result.time_validations.insert(MYSQL_ID.into(), 1);
            return Ok(result);
        }
        return compare_selection(context, selected, clocks);
    }
    let fields = selected
        .fields
        .iter()
        .map(|(pointer, contract)| Field {
            rule_id: selected.id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    Ok(json::compare_all(
        &selected.source,
        &selected.target,
        &fields,
        &[],
        &[],
        clocks,
        copies,
        context.metadata,
    ))
}
