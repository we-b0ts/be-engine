//! Expand existing Source selections once while preserving declaration order and conflicts.
use crate::delivery;
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_contract::compare::Field;
use traffic_contract::rule::FieldContract;
use traffic_policy_value::fields::SelectedGlobalField;

type Owners<'a> = BTreeMap<String, Vec<&'a FieldContract>>;

pub(super) fn append<'a>(
    source: &Value,
    mut fields: Vec<Field<'a>>,
    selected: &'a [SelectedGlobalField],
) -> Vec<Field<'a>> {
    if fields.is_empty() {
        return selected.iter().map(comparison_field).collect();
    }
    let mut owners = Owners::new();
    for field in &fields {
        index(&mut owners, source, field.pointer, field.contract);
    }
    for selected in selected {
        // Compatible contextual clocks still compose in the comparator.
        // Only an identical complete declaration at every existing owner
        // removes the duplicate; original field and rule order stay intact.
        let duplicate = owners.get(&selected.pointer).is_some_and(|contracts| {
            !contracts.is_empty()
                && contracts
                    .iter()
                    .all(|contract| **contract == selected.contract)
        });
        if !duplicate {
            index(&mut owners, source, &selected.pointer, &selected.contract);
            fields.push(comparison_field(selected));
        }
    }
    fields
}

fn comparison_field(selected: &SelectedGlobalField) -> Field<'_> {
    Field {
        rule_id: selected.rule_id,
        pointer: &selected.pointer,
        contract: &selected.contract,
    }
}

fn index<'a>(owners: &mut Owners<'a>, source: &Value, pattern: &str, contract: &'a FieldContract) {
    // The same selector retains array-only wildcards, escaped/literal keys,
    // missing Source leaves and invalid-pattern behavior from composition.
    if let Ok(paths) = delivery::select(pattern, source) {
        for pointer in paths {
            owners.entry(pointer).or_default().push(contract);
        }
    }
}

#[cfg(test)]
mod tests;
