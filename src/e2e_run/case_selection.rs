//! Select fresh repair inputs without promoting historical passes to fresh evidence.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    model::{ActiveRunState, CaseStatus, RunLayout},
    store,
    support::api_directory,
};
use crate::case_group::{CanonicalCaseGroup, CaseGroupInventory};

pub(crate) struct ReplayIteration {
    pub(crate) workflow_id: String,
    pub(crate) final_round: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CaseSelection {
    workflow_id: String,
    final_round: bool,
    groups: BTreeMap<String, GroupSelection>,
    pub(super) skipped_passed_case_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupSelection {
    inventory_id: String,
    case_ids: BTreeSet<String>,
}

impl CaseSelection {
    pub(super) fn project(&mut self, api: &str) {
        self.groups.retain(|group, _| group == api);
        self.skipped_passed_case_ids.retain(|id| {
            self.groups
                .values()
                .any(|group| group.case_ids.contains(id))
        });
    }
}

pub(super) fn prepare(
    layout: &RunLayout,
    inventory: &mut CaseGroupInventory,
    iteration: Option<&ReplayIteration>,
) -> Result<Option<CaseSelection>> {
    let Some(iteration) = iteration else {
        return Ok(None);
    };
    let retry = crate::config::regression::RegressionScope::load(&layout.target_root)?
        .retry_failed_only
        && !iteration.final_round;
    let mut selection = CaseSelection {
        workflow_id: iteration.workflow_id.clone(),
        final_round: iteration.final_round,
        groups: BTreeMap::new(),
        skipped_passed_case_ids: BTreeSet::new(),
    };
    for group in &mut inventory.groups {
        let case_ids = group
            .cases
            .iter()
            .map(|case| case.case_id.clone())
            .collect();
        selection.groups.insert(
            group.group_id.clone(),
            GroupSelection {
                inventory_id: group.case_inventory_id.clone(),
                case_ids,
            },
        );
        if !retry {
            continue;
        }
        let path = layout
            .run_root
            .join("focused")
            .join(api_directory(&group.group_id))
            .join("latest/state.yaml");
        if !path.is_file() {
            continue;
        }
        let previous: ActiveRunState = store::read_yaml(&path)?;
        if previous
            .case_selection
            .as_ref()
            .is_some_and(|selection| selection.workflow_id != iteration.workflow_id)
            || !previous.status.is_terminal()
            || previous.run_key != layout.run_key
            || previous.case_source != inventory.case_source
            || previous.source_revision != inventory.source_revision
            || validate_group(&previous, group).is_err()
        {
            continue;
        }
        let mut passed = previous
            .case_selection
            .as_ref()
            .map(|selection| selection.skipped_passed_case_ids.clone())
            .unwrap_or_default();
        passed.extend(
            previous
                .cases
                .iter()
                .filter(|case| {
                    case.group_id == group.group_id
                        && case.status == CaseStatus::Passed
                        && case.assertion_passed == Some(true)
                        && case.replay_clean == Some(true)
                        && case.execution_failure.is_none()
                })
                .map(|case| case.case_id.clone()),
        );
        // An explicit rerun of an already passing API still produces real evidence.
        if group
            .cases
            .iter()
            .all(|case| passed.contains(&case.case_id))
        {
            continue;
        }
        group.cases.retain(|case| {
            if passed.contains(&case.case_id) {
                selection
                    .skipped_passed_case_ids
                    .insert(case.case_id.clone());
                false
            } else {
                true
            }
        });
    }
    Ok(Some(selection))
}

pub(super) fn validate_group(state: &ActiveRunState, group: &CanonicalCaseGroup) -> Result<()> {
    validate_membership(
        state,
        &group.group_id,
        &group.case_inventory_id,
        group.cases.iter().map(|case| case.case_id.as_str()),
    )
}

pub(super) fn validate_membership<'a>(
    state: &ActiveRunState,
    group_id: &str,
    inventory_id: &str,
    prepared_case_ids: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let expected: BTreeSet<_> = prepared_case_ids.collect();
    let selected: BTreeSet<_> = state
        .cases
        .iter()
        .filter(|case| case.group_id == group_id)
        .map(|case| case.case_id.as_str())
        .collect();
    let skipped = if let Some(selection) = &state.case_selection {
        let declared = selection.groups.get(group_id);
        ensure!(
            declared.is_some_and(|declared| {
                declared.inventory_id == inventory_id
                    && declared
                        .case_ids
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>()
                        == expected
            }),
            "focused case selection has a different prepared API inventory"
        );
        let all_declared = selection
            .groups
            .values()
            .flat_map(|group| &group.case_ids)
            .collect::<BTreeSet<_>>();
        ensure!(
            selection
                .skipped_passed_case_ids
                .iter()
                .all(|id| all_declared.contains(id)),
            "focused case selection skips an unknown case"
        );
        ensure!(
            !selection.final_round || selection.skipped_passed_case_ids.is_empty(),
            "final Replay cannot skip previously passed cases"
        );
        selection
            .skipped_passed_case_ids
            .iter()
            .map(String::as_str)
            .filter(|id| expected.contains(id))
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    ensure!(
        !selected.is_empty()
            && selected.is_disjoint(&skipped)
            && selected.union(&skipped).copied().collect::<BTreeSet<_>>() == expected
            && state
                .cases
                .iter()
                .filter(|case| case.group_id == group_id)
                .count()
                == selected.len(),
        "focused attempt does not match the canonical API case inventory"
    );
    Ok(())
}

/// Retain the actual session membership when recovering or reclassifying evidence.
pub(super) fn restrict(inventory: &mut CaseGroupInventory, state: &ActiveRunState) -> Result<()> {
    for group in &mut inventory.groups {
        validate_group(state, group)?;
        group.cases.retain(|case| {
            state
                .cases
                .iter()
                .any(|selected| selected.case_id == case.case_id)
        });
    }
    Ok(())
}

pub(super) fn diagnosis(state: &ActiveRunState) -> Option<Value> {
    let selection = state.case_selection.as_ref()?;
    Some(json!({
        "mode":if selection.skipped_passed_case_ids.is_empty() {"full"} else {"failed_only"},
        "final_round":selection.final_round,
        "available":state.cases.len() + selection.skipped_passed_case_ids.len(),
        "selected":state.cases.len(),
        "skipped_previously_passed":selection.skipped_passed_case_ids.len(),
    }))
}

#[cfg(test)]
mod tests;
